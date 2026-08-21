from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from skilltrust.models import ContributionRequestV1, RevocationV1, TrustDomain
from skilltrust.service import SkillTrustService
from skilltrust.storage import OutboxRecord, SkillTrustStorage
from skilltrust.worker import OutboxWorker

ARTIFACT_DIGEST = "sha256:" + "a" * 64


def test_worker_delivers_known_topics(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SkillTrustService(storage=storage)
    service.submit_contribution(_contribution_request())
    service.submit_revocation(_revocation())

    worker = OutboxWorker(storage=storage, claimant="worker-a")
    summary = worker.run_once(limit=10)

    assert summary.claimed == 2
    assert summary.delivered == 2
    with storage.begin() as session:
        pending = list(
            session.scalars(select(OutboxRecord).where(OutboxRecord.delivered_at.is_(None)))
        )
        assert not pending
    storage.dispose()


def test_worker_retries_unknown_topics(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    now = datetime.now(UTC)
    with storage.begin() as session:
        storage.enqueue_outbox(
            session,
            topic="unknown.topic",
            dedupe_key="unknown-1",
            payload={"value": "x"},
            available_at=now,
        )

    worker = OutboxWorker(storage=storage, claimant="worker-a", base_retry_seconds=5)
    summary = worker.run_once(limit=10, now=now)

    assert summary.retried == 1
    with storage.begin() as session:
        row = session.scalar(select(OutboxRecord).where(OutboxRecord.topic == "unknown.topic"))
        assert row is not None
        assert row.delivered_at is None
        assert row.available_at == now + timedelta(seconds=5)
        assert row.last_error is not None
    storage.dispose()


def _storage(tmp_path: Path) -> SkillTrustStorage:
    database_path = tmp_path / "skilltrust.db"
    storage = SkillTrustStorage(f"sqlite+pysqlite:///{database_path}")
    storage.create_schema()
    return storage


def _contribution_request() -> ContributionRequestV1:
    return ContributionRequestV1(
        request_id="req-1",
        source={
            "provider": "github",
            "repository_id": "R_123",
            "clone_url": "https://github.com/acme/skills.git",
            "commit_sha": "b" * 40,
            "contribution_id": "pr-7",
        },
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
