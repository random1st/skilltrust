from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from skilltrust.models import (
    ContributionRequestV1,
    FileRecord,
    NotarizationV1,
    RevocationV1,
    SkillManifestV1,
    SourceRef,
    TrustDomain,
    TrustPolicyV1,
    ValidationResultV1,
    ValidationStatus,
    canonical_json_bytes,
    sha256_digest,
)
from skilltrust.service import (
    DEFAULT_DECLARATION_NAME,
    SkillTrustService,
    VerificationContextProvider,
    VerificationRequestV1,
)
from skilltrust.storage import OutboxRecord, SkillTrustStorage
from skilltrust.verification import (
    CatalogVerificationV1,
    SignatureVerificationV1,
    VerificationInputV1,
)

ARTIFACT_DIGEST = "sha256:" + "a" * 64
EVIDENCE_DIGEST = "sha256:" + "e" * 64
SIGNATURE_DIGEST = "sha256:" + "d" * 64
CATALOG_DIGEST = "sha256:" + "f" * 64
IDENTITY = "https://github.com/acme/skills/.github/workflows/build.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


class StaticVerificationContextProvider(VerificationContextProvider):
    def __init__(self, input_: VerificationInputV1) -> None:
        self._input = input_

    def build_input(
        self,
        *,
        artifact_digest: str,
        trust_policy: TrustPolicyV1,
        evaluated_at: datetime,
    ) -> VerificationInputV1:
        assert artifact_digest == self._input.artifact_digest
        assert trust_policy == self._input.policy
        return self._input.model_copy(update={"evaluated_at": evaluated_at})


@pytest.fixture()
def storage(tmp_path: Path) -> SkillTrustStorage:
    database_path = tmp_path / "skilltrust.db"
    instance = SkillTrustStorage(f"sqlite+pysqlite:///{database_path}")
    instance.create_schema()
    try:
        yield instance
    finally:
        instance.dispose()


def test_pack_skill_builds_manifest_and_archive(tmp_path: Path, storage: SkillTrustStorage) -> None:
    source_dir = _sample_skill_dir(tmp_path / "skill")
    service = SkillTrustService(storage=storage)
    packed = service.pack_skill(source_dir=source_dir, source=_source_ref())

    assert packed.manifest.source == _source_ref()
    assert packed.summary.file_count == 2
    assert packed.summary.source_declaration_path.endswith(DEFAULT_DECLARATION_NAME)


def test_submit_contribution_and_revocation_enqueue_outbox(
    storage: SkillTrustStorage,
) -> None:
    service = SkillTrustService(storage=storage)
    contribution = _contribution_request()
    accepted = service.submit_contribution(contribution)
    revocation = _revocation()
    revoked = service.submit_revocation(revocation)

    assert accepted.outbox_topic == "contribution.recorded"
    assert revoked.outbox_topic == "revocation.recorded"
    with storage.begin() as session:
        payloads = list(session.scalars(select(OutboxRecord.payload).order_by(OutboxRecord.id)))
    assert all("clone_url" not in payload for payload in payloads)
    assert all("requested_by" not in payload for payload in payloads)


def test_verify_artifact_without_external_context_returns_unknown_and_persists(
    storage: SkillTrustStorage,
) -> None:
    policy = _trust_policy()
    service = SkillTrustService(storage=storage, trust_policies={policy.trust_domain: policy})

    result = service.verify_artifact(
        VerificationRequestV1(
            artifact_digest=ARTIFACT_DIGEST,
            trust_domain=TrustDomain.COMMUNITY,
        )
    )

    assert result.upstream_available is False
    assert result.decision.status is ValidationStatus.UNKNOWN
    audit = service.audit_artifact(
        artifact_digest=ARTIFACT_DIGEST,
        trust_domain=TrustDomain.COMMUNITY,
    )
    assert audit.latest_decisions[0].reason_codes == ("verification_evidence_unavailable",)


def test_verify_artifact_uses_trusted_context_provider(storage: SkillTrustStorage) -> None:
    policy = _trust_policy()
    provider = StaticVerificationContextProvider(_verification_input(policy=policy))
    service = SkillTrustService(
        storage=storage,
        trust_policies={policy.trust_domain: policy},
        verification_context_provider=provider,
    )

    result = service.verify_artifact(
        VerificationRequestV1(
            artifact_digest=ARTIFACT_DIGEST,
            trust_domain=TrustDomain.COMMUNITY,
        )
    )

    assert result.upstream_available is True
    assert result.decision.status is ValidationStatus.PASS
    assert result.decision.lease_expires_at is not None


def _sample_skill_dir(path: Path) -> Path:
    path.mkdir()
    (path / "SKILL.md").write_text("# Example\n")
    (path / DEFAULT_DECLARATION_NAME).write_text(
        """\
api_version: skilltrust.dev/v1
kind: SkillSource
name: example-skill
version: 1.0.0
payload_tier: declarative
description: Example skill
"""
    )
    return path


def _source_ref() -> SourceRef:
    return SourceRef(
        provider="github",
        repository_id="R_123",
        clone_url="https://github.com/acme/skills.git",
        commit_sha="b" * 40,
        contribution_id="pr-7",
    )


def _contribution_request() -> ContributionRequestV1:
    return ContributionRequestV1(
        request_id="req-1",
        source=_source_ref(),
        manifest_digest=ARTIFACT_DIGEST,
        requested_trust_domain=TrustDomain.COMMUNITY,
        requested_by="review-bot",
        created_at=datetime.now(UTC),
        approval_subjects=("policy-review",),
    )


def _revocation() -> RevocationV1:
    now = datetime.now(UTC)
    return RevocationV1(
        revocation_id="rev-1",
        trust_domain=TrustDomain.COMMUNITY,
        artifact_digests=(ARTIFACT_DIGEST,),
        reason_code="policy-breach",
        reason="Manual intervention required",
        effective_at=now,
        issued_at=now,
        issuer="notary@example.com",
        signature_bundle_digest="sha256:" + "c" * 64,
    )


def _trust_policy() -> TrustPolicyV1:
    return TrustPolicyV1(
        policy_id="community",
        version=1,
        trust_domain=TrustDomain.COMMUNITY,
        accepted_oidc_issuers=(ISSUER,),
        accepted_identities=(IDENTITY,),
        required_validators=("archive-safety",),
        declarative_lease=timedelta(days=7),
        executable_lease=timedelta(hours=24),
        max_offline_lease=timedelta(days=7),
        runtime_capability_adapters=("sandbox-v1",),
    )


def _verification_input(*, policy: TrustPolicyV1) -> VerificationInputV1:
    now = datetime.now(UTC)
    manifest = _manifest()
    manifest_digest = sha256_digest(canonical_json_bytes(manifest))
    policy_digest = sha256_digest(canonical_json_bytes(policy))
    validator = ValidationResultV1(
        validator="archive-safety",
        validator_version="1",
        subject_digest=ARTIFACT_DIGEST,
        status=ValidationStatus.PASS,
        code="safe",
        message="Safe archive",
        evidence=(EVIDENCE_DIGEST,),
        started_at=now,
        completed_at=now,
    )
    notarization = NotarizationV1(
        artifact_digest=ARTIFACT_DIGEST,
        manifest_digest=manifest_digest,
        source=manifest.source,
        trust_domain=TrustDomain.COMMUNITY,
        builder_identity=IDENTITY,
        validation_results=(validator,),
        signature_bundle_digest=SIGNATURE_DIGEST,
        transparency_log_entry="rekor-entry",
        issued_at=now,
    )
    return VerificationInputV1(
        artifact_digest=ARTIFACT_DIGEST,
        manifest=manifest,
        notarization=notarization,
        policy=policy,
        signature=SignatureVerificationV1(
            subject_digest=ARTIFACT_DIGEST,
            trust_domain=TrustDomain.COMMUNITY,
            status=ValidationStatus.PASS,
            code="sigstore_identity_verified",
            identity=IDENTITY,
            oidc_issuer=ISSUER,
            manifest_digest=manifest_digest,
            source_commit_sha=manifest.source.commit_sha,
            policy_digest=policy_digest,
            evidence=(EVIDENCE_DIGEST,),
        ),
        catalog=CatalogVerificationV1(
            trust_domain=TrustDomain.COMMUNITY,
            artifact_digest=ARTIFACT_DIGEST,
            status=ValidationStatus.PASS,
            code="tuf_target_verified",
            checked_at=now,
            valid_until=now + timedelta(days=1),
            root_version=1,
            timestamp_version=2,
            evidence=(CATALOG_DIGEST,),
        ),
        runtime_adapter=None,
        evaluated_at=now,
    )


def _manifest() -> SkillManifestV1:
    return SkillManifestV1(
        name="safe-skill",
        version="1.0.0",
        payload_tier="declarative",
        source=_source_ref(),
        description="A safe example",
        files=(FileRecord(path="SKILL.md", digest="sha256:" + "c" * 64, size=9),),
    )
