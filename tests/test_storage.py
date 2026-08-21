from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from skilltrust.models import (
    ContributionRequestV1,
    LifecycleState,
    RevocationV1,
    TrustDomain,
)
from skilltrust.storage import (
    ApprovalRecord,
    ArtifactRecord,
    ContributionRevision,
    OutboxRecord,
    RevocationRecord,
    RevokedArtifact,
    SkillTrustStorage,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


@pytest.fixture()
def storage(tmp_path: Path) -> SkillTrustStorage:
    database_path = tmp_path / "skilltrust.db"
    instance = SkillTrustStorage(f"sqlite+pysqlite:///{database_path}")
    instance.create_schema()
    try:
        yield instance
    finally:
        instance.dispose()


def contribution_request(
    *,
    request_id: str,
    contribution_id: str,
    commit_sha: str,
    manifest_digest: str = DIGEST_A,
) -> ContributionRequestV1:
    return ContributionRequestV1(
        request_id=request_id,
        source={
            "provider": "github",
            "repository_id": "R_123",
            "clone_url": "https://github.com/acme/skills.git",
            "commit_sha": commit_sha,
            "contribution_id": contribution_id,
        },
        manifest_digest=manifest_digest,
        requested_trust_domain=TrustDomain.COMMUNITY,
        requested_by="review-bot",
        created_at=datetime.now(UTC),
        approval_subjects=("policy-review",),
    )


def revocation(
    *,
    revocation_id: str,
    artifact_digests: tuple[str, ...],
) -> RevocationV1:
    timestamp = datetime.now(UTC)
    return RevocationV1(
        revocation_id=revocation_id,
        trust_domain=TrustDomain.COMMUNITY,
        artifact_digests=artifact_digests,
        reason_code="policy-breach",
        reason="Manual intervention required",
        effective_at=timestamp,
        issued_at=timestamp,
        issuer="notary@example.com",
        signature_bundle_digest=DIGEST_C,
    )


def test_approval_binds_to_current_revision_and_updates_in_place(
    storage: SkillTrustStorage,
) -> None:
    first_request = contribution_request(
        request_id="req-1",
        contribution_id="pr-7",
        commit_sha="1" * 40,
    )
    second_request = contribution_request(
        request_id="req-2",
        contribution_id="pr-7",
        commit_sha="2" * 40,
        manifest_digest=DIGEST_B,
    )

    with storage.begin() as session:
        first_revision = storage.record_contribution_revision(session, first_request)
        initial = storage.upsert_approval(
            session,
            contribution_revision_id=first_revision.id,
            subject="policy-review",
            approver="alice@example.com",
        )
        updated = storage.upsert_approval(
            session,
            contribution_revision_id=first_revision.id,
            subject="policy-review",
            approver="bob@example.com",
        )
        approval_count = session.scalar(select(func.count()).select_from(ApprovalRecord))
        assert approval_count == 1
        assert initial.id == updated.id
        assert updated.approver == "bob@example.com"

    with storage.begin() as session:
        active = storage.get_active_approval(
            session,
            source_provider="github",
            repository_id="R_123",
            logical_contribution_id="pr-7",
            subject="policy-review",
        )
        assert active is not None
        assert active.approver == "bob@example.com"

    with storage.begin() as session:
        second_revision = storage.record_contribution_revision(session, second_request)
        stale = session.get(ContributionRevision, first_revision.id)
        assert stale is not None
        assert not stale.is_current
        assert stale.superseded_at is not None
        assert (
            storage.get_active_approval(
                session,
                source_provider="github",
                repository_id="R_123",
                logical_contribution_id="pr-7",
                subject="policy-review",
            )
            is None
        )

        fresh = storage.upsert_approval(
            session,
            contribution_revision_id=second_revision.id,
            subject="policy-review",
            approver="carol@example.com",
        )
        approval_count = session.scalar(select(func.count()).select_from(ApprovalRecord))
        assert approval_count == 2
        assert fresh.contribution_revision_id == second_revision.id

    with storage.begin() as session:
        active = storage.get_active_approval(
            session,
            source_provider="github",
            repository_id="R_123",
            logical_contribution_id="pr-7",
            subject="policy-review",
        )
        assert active is not None
        assert active.approver == "carol@example.com"

    with storage.begin() as session:
        with pytest.raises(ValueError, match="superseded"):
            storage.upsert_approval(
                session,
                contribution_revision_id=first_revision.id,
                subject="policy-review",
                approver="mallory@example.com",
            )
        with pytest.raises(ValueError, match="not required"):
            storage.upsert_approval(
                session,
                contribution_revision_id=second_revision.id,
                subject="release-admin",
                approver="mallory@example.com",
            )


def test_revocations_are_append_only_and_idempotent(storage: SkillTrustStorage) -> None:
    request = contribution_request(
        request_id="req-1",
        contribution_id="pr-7",
        commit_sha="3" * 40,
    )
    first_revocation = revocation(
        revocation_id="rev-1",
        artifact_digests=(DIGEST_B, DIGEST_B),
    )
    second_revocation = revocation(
        revocation_id="rev-2",
        artifact_digests=(DIGEST_B,),
    )

    with storage.begin() as session:
        revision = storage.record_contribution_revision(session, request)
        artifact = storage.record_artifact(
            session,
            contribution_revision_id=revision.id,
            artifact_digest=DIGEST_B,
            trust_domain=TrustDomain.COMMUNITY,
            state=LifecycleState.PUBLISHED,
        )

        first = storage.record_revocation(session, first_revocation)
        duplicate = storage.record_revocation(session, first_revocation)
        second = storage.record_revocation(session, second_revocation)

        assert first.id == duplicate.id
        assert second.id != first.id

        artifact_row = session.scalar(
            select(ArtifactRecord).where(ArtifactRecord.id == artifact.id)
        )
        assert artifact_row is not None
        assert artifact_row.state is LifecycleState.REVOKED

        revocation_count = session.scalar(select(func.count()).select_from(RevocationRecord))
        artifact_link_count = session.scalar(select(func.count()).select_from(RevokedArtifact))
        assert revocation_count == 2
        assert artifact_link_count == 2
        assert storage.is_artifact_revoked(
            session,
            trust_domain=TrustDomain.COMMUNITY,
            artifact_digest=DIGEST_B,
        )

    conflicting = first_revocation.model_copy(update={"reason": "different content"})
    with storage.begin() as session:
        with pytest.raises(ValueError, match="revocation_id replay"):
            storage.record_revocation(session, conflicting)


def test_transaction_rollback_keeps_outbox_atomic(storage: SkillTrustStorage) -> None:
    request = contribution_request(
        request_id="req-rollback",
        contribution_id="pr-rollback",
        commit_sha="4" * 40,
    )

    with pytest.raises(RuntimeError, match="boom"):
        with storage.begin() as session:
            revision = storage.record_contribution_revision(session, request)
            storage.enqueue_outbox(
                session,
                topic="artifact.review.requested",
                dedupe_key="dedupe-rollback",
                payload={
                    "revision_id": revision.id,
                    "repository_id": revision.repository_id,
                    "head_sha": revision.head_sha,
                },
            )
            raise RuntimeError("boom")

    with storage.begin() as session:
        revision_count = session.scalar(select(func.count()).select_from(ContributionRevision))
        outbox_count = session.scalar(select(func.count()).select_from(OutboxRecord))
        assert revision_count == 0
        assert outbox_count == 0

    with storage.begin() as session:
        revision = storage.record_contribution_revision(session, request)
        first = storage.enqueue_outbox(
            session,
            topic="artifact.review.requested",
            dedupe_key="dedupe-rollback",
            payload={
                "revision_id": revision.id,
                "repository_id": revision.repository_id,
                "head_sha": revision.head_sha,
            },
        )
        duplicate = storage.enqueue_outbox(
            session,
            topic="artifact.review.requested",
            dedupe_key="dedupe-rollback",
            payload={
                "revision_id": revision.id,
                "repository_id": revision.repository_id,
                "head_sha": revision.head_sha,
            },
        )
        assert duplicate.id == first.id
        with pytest.raises(ValueError, match="conflicting topic or payload"):
            storage.enqueue_outbox(
                session,
                topic="artifact.review.requested",
                dedupe_key="dedupe-rollback",
                payload={"revision_id": -1},
            )

    with storage.begin() as session:
        revision_count = session.scalar(select(func.count()).select_from(ContributionRevision))
        outbox_count = session.scalar(select(func.count()).select_from(OutboxRecord))
        assert revision_count == 1
        assert outbox_count == 1


def test_outbox_claim_retry_and_deliver_contract(storage: SkillTrustStorage) -> None:
    available_at = datetime.now(UTC)
    with storage.begin() as session:
        storage.enqueue_outbox(
            session,
            topic="artifact.published",
            dedupe_key="outbox-1",
            payload={"artifact_digest": DIGEST_A},
            available_at=available_at,
        )
        storage.enqueue_outbox(
            session,
            topic="artifact.published",
            dedupe_key="outbox-2",
            payload={"artifact_digest": DIGEST_B},
            available_at=available_at,
        )

    first_batch = storage.claim_outbox_messages(limit=1, claimant="worker-a", lease_seconds=30)
    second_batch = storage.claim_outbox_messages(limit=1, claimant="worker-b", lease_seconds=30)
    exhausted = storage.claim_outbox_messages(limit=1, claimant="worker-c", lease_seconds=30)

    assert len(first_batch) == 1
    assert len(second_batch) == 1
    assert not exhausted
    assert first_batch[0].id != second_batch[0].id
    assert first_batch[0].attempts == 1

    assert storage.mark_outbox_retry(
        outbox_id=first_batch[0].id,
        claim_token=first_batch[0].claim_token,
        next_attempt_at=available_at + timedelta(seconds=1),
        last_error="temporary failure",
    )

    retried_too_early = storage.claim_outbox_messages(
        limit=1,
        claimant="worker-d",
        lease_seconds=30,
        now=available_at,
    )
    assert not retried_too_early

    retry_batch = storage.claim_outbox_messages(
        limit=1,
        claimant="worker-d",
        lease_seconds=30,
        now=available_at + timedelta(seconds=2),
    )
    assert [message.id for message in retry_batch] == [first_batch[0].id]
    assert retry_batch[0].attempts == 2

    assert storage.mark_outbox_delivered(
        outbox_id=retry_batch[0].id,
        claim_token=retry_batch[0].claim_token,
    )
    assert storage.mark_outbox_delivered(
        outbox_id=second_batch[0].id,
        claim_token=second_batch[0].claim_token,
    )

    final_batch = storage.claim_outbox_messages(limit=10, claimant="worker-e", lease_seconds=30)
    assert not final_batch
