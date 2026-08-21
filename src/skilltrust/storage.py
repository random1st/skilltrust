"""Durable PostgreSQL-first storage for the SkillTrust control plane."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    and_,
    create_engine,
    or_,
    select,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.types import TypeDecorator

from skilltrust.models import (
    ContributionRequestV1,
    LifecycleState,
    RevocationV1,
    TrustDomain,
    ValidationStatus,
    VerificationAction,
    VerificationDecisionV1,
    canonical_json_bytes,
    sha256_digest,
    utc_now,
)

CONTRIBUTION_STATE_ENUM = Enum(LifecycleState, native_enum=False, length=32)
TRUST_DOMAIN_ENUM = Enum(TrustDomain, native_enum=False, length=32)
VALIDATION_STATUS_ENUM = Enum(ValidationStatus, native_enum=False, length=32)
VERIFICATION_ACTION_ENUM = Enum(VerificationAction, native_enum=False, length=16)
SelectRow = TypeVar("SelectRow")


class UtcDateTime(TypeDecorator[datetime]):
    """Persist timezone-aware datetimes and always materialize them in UTC."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: object,
    ) -> datetime | None:
        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(UTC)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: object,
    ) -> datetime | None:
        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    """Shared metadata with deterministic constraint naming."""

    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


class ContributionRevision(Base):
    """Exact repository revision under review.

    Deliberately excludes clone URLs or raw manifests so credentials and mutable transport
    locations are not persisted.
    """

    __tablename__ = "contribution_revisions"
    __table_args__ = (
        UniqueConstraint(
            "source_provider",
            "repository_id",
            "logical_contribution_id",
            "head_sha",
            name="uq_contribution_revision_identity",
        ),
        Index(
            "ix_contribution_revisions_current",
            "source_provider",
            "repository_id",
            "logical_contribution_id",
            "is_current",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    source_provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(512), nullable=False)
    logical_contribution_id: Mapped[str] = mapped_column(String(256), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    requested_trust_domain: Mapped[TrustDomain] = mapped_column(TRUST_DOMAIN_ENUM, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(512), nullable=False)
    approval_subjects: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    state: Mapped[LifecycleState] = mapped_column(
        CONTRIBUTION_STATE_ENUM,
        nullable=False,
        default=LifecycleState.UNTRUSTED,
    )
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    superseded_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    approvals: Mapped[list[ApprovalRecord]] = relationship(back_populates="revision")
    artifacts: Mapped[list[ArtifactRecord]] = relationship(back_populates="revision")


class ApprovalRecord(Base):
    """Review approval bound to one exact contribution revision."""

    __tablename__ = "approval_records"
    __table_args__ = (
        UniqueConstraint(
            "contribution_revision_id",
            "subject",
            name="uq_approval_revision_subject",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contribution_revision_id: Mapped[int] = mapped_column(
        ForeignKey("contribution_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    subject: Mapped[str] = mapped_column(String(256), nullable=False)
    approver: Mapped[str] = mapped_column(String(512), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    revision: Mapped[ContributionRevision] = relationship(back_populates="approvals")


class ArtifactRecord(Base):
    """Built artifact pinned to the exact source revision and trust domain."""

    __tablename__ = "artifact_records"
    __table_args__ = (
        UniqueConstraint(
            "trust_domain",
            "artifact_digest",
            name="uq_artifact_trust_domain_digest",
        ),
        Index(
            "ix_artifact_revision_lookup",
            "source_provider",
            "repository_id",
            "head_sha",
            "trust_domain",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contribution_revision_id: Mapped[int] = mapped_column(
        ForeignKey("contribution_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(512), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    artifact_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    trust_domain: Mapped[TrustDomain] = mapped_column(TRUST_DOMAIN_ENUM, nullable=False)
    state: Mapped[LifecycleState] = mapped_column(
        CONTRIBUTION_STATE_ENUM,
        nullable=False,
        default=LifecycleState.REVIEWED,
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    revision: Mapped[ContributionRevision] = relationship(back_populates="artifacts")


class RevocationRecord(Base):
    """Append-only revocation statement."""

    __tablename__ = "revocation_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revocation_id: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    trust_domain: Mapped[TrustDomain] = mapped_column(TRUST_DOMAIN_ENUM, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    effective_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    issuer: Mapped[str] = mapped_column(String(1024), nullable=False)
    signature_bundle_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)

    artifacts: Mapped[list[RevokedArtifact]] = relationship(back_populates="revocation")


class RevokedArtifact(Base):
    """Artifact membership in an append-only revocation."""

    __tablename__ = "revoked_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "revocation_record_id",
            "artifact_digest",
            name="uq_revocation_artifact",
        ),
        Index("ix_revoked_artifacts_digest", "artifact_digest"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revocation_record_id: Mapped[int] = mapped_column(
        ForeignKey("revocation_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    artifact_digest: Mapped[str] = mapped_column(String(71), nullable=False)

    revocation: Mapped[RevocationRecord] = relationship(back_populates="artifacts")


class VerificationDecisionRecord(Base):
    """Persisted verification/audit decision over one immutable artifact digest."""

    __tablename__ = "verification_decision_records"
    __table_args__ = (
        UniqueConstraint(
            "decision_digest",
            name="uq_verification_decision_digest",
        ),
        Index(
            "ix_verification_decision_lookup",
            "trust_domain",
            "artifact_digest",
            "evaluated_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    artifact_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    trust_domain: Mapped[TrustDomain] = mapped_column(TRUST_DOMAIN_ENUM, nullable=False)
    policy_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    action: Mapped[VerificationAction] = mapped_column(VERIFICATION_ACTION_ENUM, nullable=False)
    status: Mapped[ValidationStatus] = mapped_column(VALIDATION_STATUS_ENUM, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evaluated_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)


class OutboxRecord(Base):
    """Transactional outbox with at-least-once delivery semantics."""

    __tablename__ = "outbox_records"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_outbox_dedupe_key"),
        Index(
            "ix_outbox_pending",
            "delivered_at",
            "available_at",
            "claim_deadline_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    available_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)
    claimant: Mapped[str | None] = mapped_column(String(256), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    claim_deadline_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delivered_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


@dataclass(frozen=True, slots=True)
class ClaimedOutboxMessage:
    """Detached outbox claim payload returned after the claim transaction commits."""

    id: int
    topic: str
    dedupe_key: str
    payload: dict[str, object]
    claim_token: str
    claimant: str
    attempts: int
    available_at: datetime
    claimed_at: datetime
    claim_deadline_at: datetime


def create_storage_engine(database_url: str) -> Engine:
    """Create a production-ready engine with SQLite-safe local defaults."""

    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)


class SkillTrustStorage:
    """SQLAlchemy-backed durable storage and transactional outbox."""

    def __init__(self, database_url: str, *, engine: Engine | None = None) -> None:
        self.engine = engine if engine is not None else create_storage_engine(database_url)
        self._session_factory = sessionmaker(self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def dispose(self) -> None:
        self.engine.dispose()

    @contextmanager
    def begin(self) -> Iterator[Session]:
        with self._session_factory.begin() as session:
            yield session

    def record_contribution_revision(
        self,
        session: Session,
        request: ContributionRequestV1,
        *,
        state: LifecycleState = LifecycleState.UNTRUSTED,
    ) -> ContributionRevision:
        existing_by_request = session.scalar(
            select(ContributionRevision).where(
                ContributionRevision.request_id == request.request_id
            )
        )
        if existing_by_request is not None:
            self._validate_replayed_request(existing_by_request, request, state)
            return existing_by_request

        logical_contribution_id = request.source.contribution_id or request.request_id
        current_rows = list(
            session.scalars(
                self._maybe_lock(
                    session,
                    select(ContributionRevision).where(
                        ContributionRevision.source_provider == request.source.provider,
                        ContributionRevision.repository_id == request.source.repository_id,
                        ContributionRevision.logical_contribution_id == logical_contribution_id,
                        ContributionRevision.is_current.is_(True),
                    ),
                )
            )
        )
        now = utc_now()
        for row in current_rows:
            if row.head_sha != request.source.commit_sha:
                row.is_current = False
                row.superseded_at = now
                row.updated_at = now

        revision = ContributionRevision(
            request_id=request.request_id,
            source_provider=request.source.provider,
            repository_id=request.source.repository_id,
            logical_contribution_id=logical_contribution_id,
            head_sha=request.source.commit_sha,
            manifest_digest=request.manifest_digest,
            requested_trust_domain=request.requested_trust_domain,
            requested_by=request.requested_by,
            approval_subjects=list(request.approval_subjects),
            state=state,
            is_current=True,
        )
        session.add(revision)
        try:
            session.flush()
        except IntegrityError as exc:
            raise ValueError(
                "duplicate contribution revision with conflicting request identity"
            ) from exc
        return revision

    def get_current_revision(
        self,
        session: Session,
        *,
        source_provider: str,
        repository_id: str,
        logical_contribution_id: str,
    ) -> ContributionRevision | None:
        return session.scalar(
            select(ContributionRevision).where(
                ContributionRevision.source_provider == source_provider,
                ContributionRevision.repository_id == repository_id,
                ContributionRevision.logical_contribution_id == logical_contribution_id,
                ContributionRevision.is_current.is_(True),
            )
        )

    def upsert_approval(
        self,
        session: Session,
        *,
        contribution_revision_id: int,
        subject: str,
        approver: str,
        recorded_at: datetime | None = None,
    ) -> ApprovalRecord:
        timestamp = recorded_at or utc_now()
        revision = session.get(ContributionRevision, contribution_revision_id)
        if revision is None:
            raise ValueError(f"unknown contribution revision {contribution_revision_id}")
        if not revision.is_current:
            raise ValueError("cannot approve a superseded contribution revision")
        if subject not in revision.approval_subjects:
            raise ValueError(f"approval subject '{subject}' is not required by this contribution")
        approval = session.scalar(
            self._maybe_lock(
                session,
                select(ApprovalRecord).where(
                    ApprovalRecord.contribution_revision_id == contribution_revision_id,
                    ApprovalRecord.subject == subject,
                ),
            )
        )
        if approval is None:
            approval = ApprovalRecord(
                contribution_revision_id=contribution_revision_id,
                subject=subject,
                approver=approver,
                recorded_at=timestamp,
            )
            session.add(approval)
            session.flush()
            return approval

        approval.approver = approver
        approval.recorded_at = timestamp
        approval.updated_at = utc_now()
        session.flush()
        return approval

    def get_active_approval(
        self,
        session: Session,
        *,
        source_provider: str,
        repository_id: str,
        logical_contribution_id: str,
        subject: str,
    ) -> ApprovalRecord | None:
        return session.scalar(
            select(ApprovalRecord)
            .join(ApprovalRecord.revision)
            .where(
                ContributionRevision.source_provider == source_provider,
                ContributionRevision.repository_id == repository_id,
                ContributionRevision.logical_contribution_id == logical_contribution_id,
                ContributionRevision.is_current.is_(True),
                ApprovalRecord.subject == subject,
            )
        )

    def record_artifact(
        self,
        session: Session,
        *,
        contribution_revision_id: int,
        artifact_digest: str,
        trust_domain: TrustDomain,
        state: LifecycleState = LifecycleState.REVIEWED,
    ) -> ArtifactRecord:
        revision = session.get(ContributionRevision, contribution_revision_id)
        if revision is None:
            raise ValueError(f"unknown contribution revision {contribution_revision_id}")

        artifact = session.scalar(
            select(ArtifactRecord).where(
                ArtifactRecord.trust_domain == trust_domain,
                ArtifactRecord.artifact_digest == artifact_digest,
            )
        )
        if artifact is None:
            artifact = ArtifactRecord(
                contribution_revision_id=revision.id,
                source_provider=revision.source_provider,
                repository_id=revision.repository_id,
                head_sha=revision.head_sha,
                manifest_digest=revision.manifest_digest,
                artifact_digest=artifact_digest,
                trust_domain=trust_domain,
                state=state,
            )
            session.add(artifact)
            session.flush()
            return artifact

        if artifact.contribution_revision_id != revision.id:
            raise ValueError("artifact digest already belongs to a different contribution revision")
        artifact.state = state
        artifact.updated_at = utc_now()
        session.flush()
        return artifact

    def record_verification_decision(
        self,
        session: Session,
        decision: VerificationDecisionV1,
    ) -> VerificationDecisionRecord:
        decision_digest = sha256_digest(canonical_json_bytes(decision))
        existing = session.scalar(
            select(VerificationDecisionRecord).where(
                VerificationDecisionRecord.decision_digest == decision_digest
            )
        )
        if existing is not None:
            return existing

        record = VerificationDecisionRecord(
            decision_digest=decision_digest,
            artifact_digest=decision.artifact_digest,
            trust_domain=decision.trust_domain,
            policy_digest=decision.policy_digest,
            action=decision.action,
            status=decision.status,
            reason_codes=list(decision.reason_codes),
            evidence=list(decision.evidence),
            evaluated_at=decision.evaluated_at,
            lease_expires_at=decision.lease_expires_at,
        )
        session.add(record)
        session.flush()
        return record

    def record_revocation(
        self,
        session: Session,
        revocation: RevocationV1,
    ) -> RevocationRecord:
        existing = session.scalar(
            select(RevocationRecord).where(
                RevocationRecord.revocation_id == revocation.revocation_id
            )
        )
        if existing is not None:
            stored_artifacts = {item.artifact_digest for item in existing.artifacts}
            proposed_artifacts = set(revocation.artifact_digests)
            if (
                existing.trust_domain is not revocation.trust_domain
                or existing.reason_code != revocation.reason_code
                or existing.reason != revocation.reason
                or existing.effective_at != revocation.effective_at
                or existing.issued_at != revocation.issued_at
                or existing.issuer != revocation.issuer
                or existing.signature_bundle_digest != revocation.signature_bundle_digest
                or stored_artifacts != proposed_artifacts
            ):
                raise ValueError("revocation_id replay does not match the stored revocation")
            return existing

        record = RevocationRecord(
            revocation_id=revocation.revocation_id,
            trust_domain=revocation.trust_domain,
            reason_code=revocation.reason_code,
            reason=revocation.reason,
            effective_at=revocation.effective_at,
            issued_at=revocation.issued_at,
            issuer=revocation.issuer,
            signature_bundle_digest=revocation.signature_bundle_digest,
        )
        session.add(record)
        session.flush()

        artifact_digests = list(dict.fromkeys(revocation.artifact_digests))
        session.add_all(
            [
                RevokedArtifact(
                    revocation_record_id=record.id,
                    artifact_digest=artifact_digest,
                )
                for artifact_digest in artifact_digests
            ]
        )
        now = utc_now()
        session.execute(
            update(ArtifactRecord)
            .where(
                ArtifactRecord.trust_domain == revocation.trust_domain,
                ArtifactRecord.artifact_digest.in_(artifact_digests),
            )
            .values(state=LifecycleState.REVOKED, updated_at=now)
        )
        session.flush()
        return record

    def is_artifact_revoked(
        self,
        session: Session,
        *,
        trust_domain: TrustDomain,
        artifact_digest: str,
        effective_at: datetime | None = None,
    ) -> bool:
        observed_at = effective_at or utc_now()
        revoked = session.scalar(
            select(RevokedArtifact.id)
            .join(RevokedArtifact.revocation)
            .where(
                RevocationRecord.trust_domain == trust_domain,
                RevokedArtifact.artifact_digest == artifact_digest,
                RevocationRecord.effective_at <= observed_at,
            )
            .limit(1)
        )
        return revoked is not None

    def enqueue_outbox(
        self,
        session: Session,
        *,
        topic: str,
        dedupe_key: str,
        payload: dict[str, object],
        available_at: datetime | None = None,
    ) -> OutboxRecord:
        existing = session.scalar(select(OutboxRecord).where(OutboxRecord.dedupe_key == dedupe_key))
        if existing is not None:
            if existing.topic != topic or existing.payload != payload:
                raise ValueError("outbox dedupe_key replay has a conflicting topic or payload")
            if available_at is not None and existing.available_at != available_at:
                raise ValueError("outbox dedupe_key replay has a conflicting availability time")
            return existing

        record = OutboxRecord(
            topic=topic,
            dedupe_key=dedupe_key,
            payload=payload,
            available_at=available_at or utc_now(),
        )
        session.add(record)
        session.flush()
        return record

    def claim_outbox_messages(
        self,
        *,
        limit: int,
        claimant: str,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> list[ClaimedOutboxMessage]:
        if limit < 1:
            raise ValueError("limit must be positive")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")

        claimed_at = now or utc_now()
        claim_deadline_at = claimed_at + timedelta(seconds=lease_seconds)
        claim_token = uuid.uuid4().hex
        with self.begin() as session:
            rows = self._claim_outbox_rows(
                session,
                limit=limit,
                claimant=claimant,
                claim_token=claim_token,
                claimed_at=claimed_at,
                claim_deadline_at=claim_deadline_at,
            )
            return [self._to_claim(row) for row in rows]

    def mark_outbox_delivered(
        self,
        *,
        outbox_id: int,
        claim_token: str,
        delivered_at: datetime | None = None,
    ) -> bool:
        timestamp = delivered_at or utc_now()
        with self.begin() as session:
            delivered = session.execute(
                update(OutboxRecord)
                .where(
                    OutboxRecord.id == outbox_id,
                    OutboxRecord.claim_token == claim_token,
                    OutboxRecord.delivered_at.is_(None),
                )
                .values(delivered_at=timestamp, updated_at=timestamp)
                .returning(OutboxRecord.id)
            ).scalar_one_or_none()
            return delivered is not None

    def mark_outbox_retry(
        self,
        *,
        outbox_id: int,
        claim_token: str,
        next_attempt_at: datetime | None = None,
        last_error: str | None = None,
    ) -> bool:
        timestamp = utc_now()
        available_at = next_attempt_at or timestamp
        with self.begin() as session:
            retried = session.execute(
                update(OutboxRecord)
                .where(
                    OutboxRecord.id == outbox_id,
                    OutboxRecord.claim_token == claim_token,
                    OutboxRecord.delivered_at.is_(None),
                )
                .values(
                    available_at=available_at,
                    claimant=None,
                    claim_token=None,
                    claimed_at=None,
                    claim_deadline_at=None,
                    last_error=last_error,
                    updated_at=timestamp,
                )
                .returning(OutboxRecord.id)
            ).scalar_one_or_none()
            return retried is not None

    def _claim_outbox_rows(
        self,
        session: Session,
        *,
        limit: int,
        claimant: str,
        claim_token: str,
        claimed_at: datetime,
        claim_deadline_at: datetime,
    ) -> list[OutboxRecord]:
        dialect_name = session.get_bind().dialect.name
        pending = self._pending_outbox_filter(claimed_at)
        if dialect_name == "sqlite":
            subquery = (
                select(OutboxRecord.id)
                .where(*pending)
                .order_by(OutboxRecord.available_at, OutboxRecord.id)
                .limit(limit)
            )
            return list(
                session.execute(
                    update(OutboxRecord)
                    .where(OutboxRecord.id.in_(subquery), *pending)
                    .values(
                        claimant=claimant,
                        claim_token=claim_token,
                        claimed_at=claimed_at,
                        claim_deadline_at=claim_deadline_at,
                        attempts=OutboxRecord.attempts + 1,
                        updated_at=claimed_at,
                    )
                    .returning(OutboxRecord)
                ).scalars()
            )

        lock_query = (
            select(OutboxRecord)
            .where(*pending)
            .order_by(
                OutboxRecord.available_at,
                OutboxRecord.id,
            )
        )
        if dialect_name == "postgresql":
            lock_query = lock_query.with_for_update(skip_locked=True)
        else:
            lock_query = lock_query.with_for_update()

        rows = list(session.scalars(lock_query.limit(limit)))
        for row in rows:
            row.claimant = claimant
            row.claim_token = claim_token
            row.claimed_at = claimed_at
            row.claim_deadline_at = claim_deadline_at
            row.attempts += 1
            row.updated_at = claimed_at
        session.flush()
        return rows

    def _pending_outbox_filter(self, now: datetime) -> tuple[ColumnElement[bool], ...]:
        return (
            OutboxRecord.delivered_at.is_(None),
            OutboxRecord.available_at <= now,
            or_(
                OutboxRecord.claim_deadline_at.is_(None),
                and_(
                    OutboxRecord.claim_token.is_not(None),
                    OutboxRecord.claim_deadline_at < now,
                ),
            ),
        )

    def _validate_replayed_request(
        self,
        existing: ContributionRevision,
        request: ContributionRequestV1,
        state: LifecycleState,
    ) -> None:
        logical_contribution_id = request.source.contribution_id or request.request_id
        if (
            existing.source_provider != request.source.provider
            or existing.repository_id != request.source.repository_id
            or existing.logical_contribution_id != logical_contribution_id
            or existing.head_sha != request.source.commit_sha
            or existing.manifest_digest != request.manifest_digest
            or existing.requested_trust_domain is not request.requested_trust_domain
            or existing.requested_by != request.requested_by
            or existing.approval_subjects != list(request.approval_subjects)
            or existing.state is not state
        ):
            raise ValueError("request_id replay does not match the stored contribution revision")

    def _maybe_lock(
        self,
        session: Session,
        statement: Select[tuple[SelectRow]],
    ) -> Select[tuple[SelectRow]]:
        if session.get_bind().dialect.name == "postgresql":
            return statement.with_for_update()
        return statement

    def _to_claim(self, row: OutboxRecord) -> ClaimedOutboxMessage:
        if row.claim_token is None or row.claimant is None:
            raise ValueError("claimed outbox row is missing claim metadata")
        if row.claimed_at is None or row.claim_deadline_at is None:
            raise ValueError("claimed outbox row is missing claim timestamps")
        return ClaimedOutboxMessage(
            id=row.id,
            topic=row.topic,
            dedupe_key=row.dedupe_key,
            payload=dict(row.payload),
            claim_token=row.claim_token,
            claimant=row.claimant,
            attempts=row.attempts,
            available_at=row.available_at,
            claimed_at=row.claimed_at,
            claim_deadline_at=row.claim_deadline_at,
        )


__all__ = [
    "ApprovalRecord",
    "ArtifactRecord",
    "Base",
    "ClaimedOutboxMessage",
    "ContributionRevision",
    "OutboxRecord",
    "RevocationRecord",
    "RevokedArtifact",
    "SkillTrustStorage",
    "UtcDateTime",
    "VerificationDecisionRecord",
    "create_storage_engine",
]
