"""Application-facing orchestration over the strict SkillTrust domain contracts."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import Field
from sqlalchemy import select

from skilltrust.archive import ArchiveError, BuiltArchive, build_archive, extract_archive
from skilltrust.cas import CasError, ContentAddressableStore, StoredArtifact
from skilltrust.models import (
    ContributionRequestV1,
    FileRecord,
    LifecycleState,
    RevocationV1,
    Sha256,
    SkillManifestV1,
    SourceRef,
    StrictModel,
    TrustDomain,
    TrustPolicyV1,
    ValidationStatus,
    VerificationAction,
    VerificationDecisionV1,
    canonical_json_bytes,
    sha256_digest,
    utc_now,
)
from skilltrust.schemas import SCHEMAS, write_schemas
from skilltrust.source import SourceDeclarationError, load_source_declaration, materialize_manifest
from skilltrust.storage import (
    ArtifactRecord,
    RevocationRecord,
    RevokedArtifact,
    SkillTrustStorage,
    VerificationDecisionRecord,
)
from skilltrust.verification import VerificationInputV1, verify

CONTRIBUTION_RECORDED_TOPIC = "contribution.recorded"
REVOCATION_RECORDED_TOPIC = "revocation.recorded"
DEFAULT_DECLARATION_NAME = "skilltrust.yaml"


class ServiceError(RuntimeError):
    """Structured application error shared by the CLI and API surfaces."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
        status_code: int = 400,
        exit_code: int = 1,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})
        self.status_code = status_code
        self.exit_code = exit_code


class ErrorResponseV1(StrictModel):
    code: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class PackSummaryV1(StrictModel):
    source_declaration_path: str
    manifest: SkillManifestV1
    manifest_digest: Sha256
    archive_digest: Sha256
    file_count: int
    total_file_bytes: int
    archive_bytes: int


class ArchiveInspectionV1(StrictModel):
    archive_digest: Sha256
    file_count: int
    total_file_bytes: int
    files: tuple[FileRecord, ...]


class CasStateV1(StrictModel):
    digest: Sha256
    path: str
    file_count: int
    files: tuple[FileRecord, ...]


class SchemaGenerationV1(StrictModel):
    destination: str
    schema_files: tuple[str, ...]


class ContributionAcceptedV1(StrictModel):
    request_id: str
    revision_id: int
    state: LifecycleState
    outbox_id: int
    outbox_topic: str


class RevocationAcceptedV1(StrictModel):
    revocation_id: str
    record_id: int
    outbox_id: int
    outbox_topic: str
    artifact_count: int


class VerificationRequestV1(StrictModel):
    artifact_digest: Sha256
    trust_domain: TrustDomain


class VerificationResponseV1(StrictModel):
    decision: VerificationDecisionV1
    upstream_available: bool
    error_code: str | None = None


class ArtifactAuditV1(StrictModel):
    artifact_digest: Sha256
    trust_domain: TrustDomain
    lifecycle_state: LifecycleState | None = None
    revoked: bool
    revocation_ids: tuple[str, ...] = ()
    latest_decisions: tuple[VerificationDecisionV1, ...] = ()


@dataclass(frozen=True, slots=True)
class PackedSkill:
    manifest: SkillManifestV1
    manifest_digest: Sha256
    archive: BuiltArchive
    source_declaration_path: Path

    @property
    def summary(self) -> PackSummaryV1:
        return PackSummaryV1(
            source_declaration_path=str(self.source_declaration_path),
            manifest=self.manifest,
            manifest_digest=self.manifest_digest,
            archive_digest=self.archive.digest,
            file_count=len(self.archive.files),
            total_file_bytes=sum(record.size for record in self.archive.files),
            archive_bytes=len(self.archive.payload),
        )


@runtime_checkable
class VerificationContextProvider(Protocol):
    """Trusted adapter that resolves all verification evidence for an immutable artifact."""

    def build_input(
        self,
        *,
        artifact_digest: Sha256,
        trust_policy: TrustPolicyV1,
        evaluated_at: datetime,
    ) -> VerificationInputV1: ...


class SkillTrustService:
    """Thin orchestration layer that preserves the repo's fail-closed core invariants."""

    def __init__(
        self,
        *,
        storage: SkillTrustStorage,
        trust_policies: Mapping[TrustDomain, TrustPolicyV1] | None = None,
        verification_context_provider: VerificationContextProvider | None = None,
    ) -> None:
        self._storage = storage
        self._trust_policies = dict(trust_policies or {})
        self._verification_context_provider = verification_context_provider

    def pack_skill(
        self,
        *,
        source_dir: Path,
        source: SourceRef,
        declaration_name: str = DEFAULT_DECLARATION_NAME,
    ) -> PackedSkill:
        declaration_path = source_dir / declaration_name
        try:
            declaration = load_source_declaration(declaration_path)
            archive = build_archive(source_dir)
            manifest = materialize_manifest(
                declaration,
                source=source,
                files=archive.files,
            )
        except SourceDeclarationError as exc:
            raise ServiceError(
                "source_declaration_invalid",
                str(exc),
                details={"path": str(declaration_path)},
            ) from exc
        except ArchiveError as exc:
            raise ServiceError(
                "archive_build_failed",
                str(exc),
                details={"source_dir": str(source_dir)},
            ) from exc

        return PackedSkill(
            manifest=manifest,
            manifest_digest=sha256_digest(canonical_json_bytes(manifest)),
            archive=archive,
            source_declaration_path=declaration_path,
        )

    def inspect_archive(self, archive_path: Path) -> ArchiveInspectionV1:
        payload = self._read_bytes(archive_path, code="archive_unreadable")
        try:
            with tempfile.TemporaryDirectory(prefix="skilltrust-inspect-") as temporary:
                files = extract_archive(payload, Path(temporary))
        except ArchiveError as exc:
            raise ServiceError(
                "archive_invalid",
                str(exc),
                details={"archive_path": str(archive_path)},
            ) from exc
        return ArchiveInspectionV1(
            archive_digest=sha256_digest(payload),
            file_count=len(files),
            total_file_bytes=sum(record.size for record in files),
            files=files,
        )

    def ingest_archive(
        self,
        *,
        cas_root: Path,
        archive_path: Path,
        expected_digest: str | None = None,
    ) -> CasStateV1:
        payload = self._read_bytes(archive_path, code="archive_unreadable")
        digest = sha256_digest(payload) if expected_digest is None else expected_digest
        store = ContentAddressableStore(cas_root)
        try:
            stored = store.ingest_archive(payload, expected_digest=digest)
        except CasError as exc:
            raise ServiceError(
                "cas_ingest_failed",
                str(exc),
                details={"archive_path": str(archive_path), "cas_root": str(cas_root)},
            ) from exc
        return self._cas_state(stored)

    def activate_artifact(self, *, cas_root: Path, digest: str) -> CasStateV1:
        store = ContentAddressableStore(cas_root)
        try:
            stored = store.activate(digest)
        except CasError as exc:
            raise ServiceError(
                "cas_activate_failed",
                str(exc),
                details={"digest": digest, "cas_root": str(cas_root)},
            ) from exc
        return self._cas_state(stored)

    def generate_schemas(self, destination: Path) -> SchemaGenerationV1:
        try:
            write_schemas(destination)
        except OSError as exc:
            raise ServiceError(
                "schema_generation_failed",
                f"cannot write schemas to {destination}: {exc}",
                details={"destination": str(destination)},
            ) from exc
        return SchemaGenerationV1(
            destination=str(destination),
            schema_files=tuple(sorted(SCHEMAS)),
        )

    def submit_contribution(self, request: ContributionRequestV1) -> ContributionAcceptedV1:
        with self._storage.begin() as session:
            revision = self._storage.record_contribution_revision(session, request)
            outbox = self._storage.enqueue_outbox(
                session,
                topic=CONTRIBUTION_RECORDED_TOPIC,
                dedupe_key=f"contribution:{request.request_id}",
                payload={
                    "request_id": request.request_id,
                    "revision_id": revision.id,
                    "repository_id": revision.repository_id,
                    "head_sha": revision.head_sha,
                    "logical_contribution_id": revision.logical_contribution_id,
                    "trust_domain": revision.requested_trust_domain.value,
                },
            )
            return ContributionAcceptedV1(
                request_id=request.request_id,
                revision_id=revision.id,
                state=revision.state,
                outbox_id=outbox.id,
                outbox_topic=outbox.topic,
            )

    def submit_revocation(self, revocation: RevocationV1) -> RevocationAcceptedV1:
        with self._storage.begin() as session:
            record = self._storage.record_revocation(session, revocation)
            outbox = self._storage.enqueue_outbox(
                session,
                topic=REVOCATION_RECORDED_TOPIC,
                dedupe_key=f"revocation:{revocation.revocation_id}",
                payload={
                    "revocation_id": revocation.revocation_id,
                    "trust_domain": revocation.trust_domain.value,
                    "artifact_digests": list(dict.fromkeys(revocation.artifact_digests)),
                },
            )
            return RevocationAcceptedV1(
                revocation_id=revocation.revocation_id,
                record_id=record.id,
                outbox_id=outbox.id,
                outbox_topic=outbox.topic,
                artifact_count=len(dict.fromkeys(revocation.artifact_digests)),
            )

    def verify_artifact(self, request: VerificationRequestV1) -> VerificationResponseV1:
        policy = self._trust_policies.get(request.trust_domain)
        if policy is None:
            raise ServiceError(
                "trust_policy_unavailable",
                f"no local trust policy is configured for domain '{request.trust_domain.value}'",
                details={"trust_domain": request.trust_domain.value},
                status_code=503,
                exit_code=3,
            )

        evaluated_at = utc_now()
        if self._verification_context_provider is None:
            decision = VerificationDecisionV1(
                action=VerificationAction.DENY,
                status=ValidationStatus.UNKNOWN,
                artifact_digest=request.artifact_digest,
                trust_domain=request.trust_domain,
                policy_digest=sha256_digest(canonical_json_bytes(policy)),
                reason_codes=("verification_evidence_unavailable",),
                evaluated_at=evaluated_at,
            )
            self._persist_decision(decision)
            return VerificationResponseV1(
                decision=decision,
                upstream_available=False,
                error_code="verification_evidence_unavailable",
            )

        input_ = self._verification_context_provider.build_input(
            artifact_digest=request.artifact_digest,
            trust_policy=policy,
            evaluated_at=evaluated_at,
        )
        if input_.artifact_digest != request.artifact_digest:
            raise ServiceError(
                "verification_subject_mismatch",
                "trusted verification context returned a different artifact digest",
                details={"requested_digest": request.artifact_digest},
                status_code=502,
                exit_code=3,
            )
        if input_.policy != policy:
            raise ServiceError(
                "verification_policy_mismatch",
                "trusted verification context returned a different trust policy",
                details={"trust_domain": request.trust_domain.value},
                status_code=502,
                exit_code=3,
            )
        if input_.notarization.trust_domain is not request.trust_domain:
            raise ServiceError(
                "verification_domain_mismatch",
                "trusted verification context crossed trust domains",
                details={"trust_domain": request.trust_domain.value},
                status_code=502,
                exit_code=3,
            )

        decision = verify(input_)
        self._persist_decision(decision)
        return VerificationResponseV1(decision=decision, upstream_available=True)

    def audit_artifact(
        self,
        *,
        artifact_digest: Sha256,
        trust_domain: TrustDomain,
        decision_limit: int = 10,
    ) -> ArtifactAuditV1:
        if decision_limit < 1 or decision_limit > 50:
            raise ServiceError(
                "decision_limit_out_of_range",
                "decision_limit must be between 1 and 50",
                details={"decision_limit": decision_limit},
            )

        with self._storage.begin() as session:
            artifact = session.scalar(
                select(ArtifactRecord)
                .where(
                    ArtifactRecord.artifact_digest == artifact_digest,
                    ArtifactRecord.trust_domain == trust_domain,
                )
                .order_by(ArtifactRecord.updated_at.desc(), ArtifactRecord.id.desc())
                .limit(1)
            )
            revocation_ids = tuple(
                session.scalars(
                    select(RevocationRecord.revocation_id)
                    .join(RevocationRecord.artifacts)
                    .where(
                        RevocationRecord.trust_domain == trust_domain,
                        RevokedArtifact.artifact_digest == artifact_digest,
                    )
                    .order_by(RevocationRecord.issued_at.desc(), RevocationRecord.id.desc())
                )
            )
            latest_decisions = tuple(
                self._record_to_decision(row)
                for row in session.scalars(
                    select(VerificationDecisionRecord)
                    .where(
                        VerificationDecisionRecord.artifact_digest == artifact_digest,
                        VerificationDecisionRecord.trust_domain == trust_domain,
                    )
                    .order_by(
                        VerificationDecisionRecord.evaluated_at.desc(),
                        VerificationDecisionRecord.id.desc(),
                    )
                    .limit(decision_limit)
                )
            )

        return ArtifactAuditV1(
            artifact_digest=artifact_digest,
            trust_domain=trust_domain,
            lifecycle_state=None if artifact is None else artifact.state,
            revoked=bool(revocation_ids),
            revocation_ids=revocation_ids,
            latest_decisions=latest_decisions,
        )

    @staticmethod
    def atomic_write_bytes(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _persist_decision(self, decision: VerificationDecisionV1) -> None:
        with self._storage.begin() as session:
            self._storage.record_verification_decision(session, decision)

    @staticmethod
    def _cas_state(stored: StoredArtifact) -> CasStateV1:
        return CasStateV1(
            digest=stored.digest,
            path=str(stored.path),
            file_count=len(stored.files),
            files=stored.files,
        )

    @staticmethod
    def _record_to_decision(record: VerificationDecisionRecord) -> VerificationDecisionV1:
        return VerificationDecisionV1(
            action=record.action,
            status=record.status,
            artifact_digest=record.artifact_digest,
            trust_domain=record.trust_domain,
            policy_digest=record.policy_digest,
            reason_codes=tuple(record.reason_codes),
            evaluated_at=record.evaluated_at,
            lease_expires_at=record.lease_expires_at,
            evidence=tuple(record.evidence),
        )

    @staticmethod
    def _read_bytes(path: Path, *, code: str) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ServiceError(
                code,
                f"cannot read {path}: {exc}",
                details={"path": str(path)},
            ) from exc


__all__ = [
    "CONTRIBUTION_RECORDED_TOPIC",
    "DEFAULT_DECLARATION_NAME",
    "REVOCATION_RECORDED_TOPIC",
    "ArchiveInspectionV1",
    "ArtifactAuditV1",
    "ContributionAcceptedV1",
    "ErrorResponseV1",
    "PackSummaryV1",
    "PackedSkill",
    "RevocationAcceptedV1",
    "SchemaGenerationV1",
    "ServiceError",
    "SkillTrustService",
    "VerificationContextProvider",
    "VerificationRequestV1",
    "VerificationResponseV1",
]
