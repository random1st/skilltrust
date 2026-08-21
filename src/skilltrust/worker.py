"""Safe worker loop for processing the transactional outbox."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from sqlalchemy import select

from skilltrust.models import StrictModel
from skilltrust.service import CONTRIBUTION_RECORDED_TOPIC, REVOCATION_RECORDED_TOPIC
from skilltrust.storage import (
    ClaimedOutboxMessage,
    ContributionRevision,
    RevocationRecord,
    RevokedArtifact,
    SkillTrustStorage,
)


class OutboxHandlerError(RuntimeError):
    """A known message could not be processed and should be retried."""


@runtime_checkable
class OutboxHandler(Protocol):
    def handle(self, *, storage: SkillTrustStorage, message: ClaimedOutboxMessage) -> None: ...


class WorkerSummaryV1(StrictModel):
    claimed: int
    delivered: int
    retried: int


class ContributionRecordedHandler:
    def handle(self, *, storage: SkillTrustStorage, message: ClaimedOutboxMessage) -> None:
        revision_id = _require_int(message.payload, "revision_id")
        repository_id = _require_str(message.payload, "repository_id")
        head_sha = _require_str(message.payload, "head_sha")
        logical_contribution_id = _require_str(message.payload, "logical_contribution_id")
        with storage.begin() as session:
            revision = session.get(ContributionRevision, revision_id)
            if revision is None:
                raise OutboxHandlerError(f"unknown contribution revision {revision_id}")
            if revision.repository_id != repository_id or revision.head_sha != head_sha:
                raise OutboxHandlerError(
                    "contribution outbox payload does not match stored revision"
                )
            if revision.logical_contribution_id != logical_contribution_id:
                raise OutboxHandlerError(
                    "contribution logical id does not match the stored revision"
                )


class RevocationRecordedHandler:
    def handle(self, *, storage: SkillTrustStorage, message: ClaimedOutboxMessage) -> None:
        revocation_id = _require_str(message.payload, "revocation_id")
        trust_domain = _require_str(message.payload, "trust_domain")
        artifact_digests = _require_digest_list(message.payload, "artifact_digests")
        with storage.begin() as session:
            record = session.scalar(
                select(RevocationRecord).where(RevocationRecord.revocation_id == revocation_id)
            )
            if record is None:
                raise OutboxHandlerError(f"unknown revocation '{revocation_id}'")
            if record.trust_domain.value != trust_domain:
                raise OutboxHandlerError("revocation trust domain does not match the stored record")
            stored_digests = tuple(
                session.scalars(
                    select(RevokedArtifact.artifact_digest).where(
                        RevokedArtifact.revocation_record_id == record.id
                    )
                )
            )
            if tuple(dict.fromkeys(stored_digests)) != artifact_digests:
                raise OutboxHandlerError(
                    "revocation artifact digests do not match the stored record"
                )


DEFAULT_HANDLER_REGISTRY: Mapping[str, OutboxHandler] = {
    CONTRIBUTION_RECORDED_TOPIC: ContributionRecordedHandler(),
    REVOCATION_RECORDED_TOPIC: RevocationRecordedHandler(),
}


@dataclass(frozen=True, slots=True)
class OutboxWorker:
    storage: SkillTrustStorage
    claimant: str
    handler_registry: Mapping[str, OutboxHandler] = field(
        default_factory=lambda: DEFAULT_HANDLER_REGISTRY
    )
    lease_seconds: int = 60
    base_retry_seconds: int = 5
    max_retry_seconds: int = 300

    def run_once(self, *, limit: int = 10, now: datetime | None = None) -> WorkerSummaryV1:
        claimed = self.storage.claim_outbox_messages(
            limit=limit,
            claimant=self.claimant,
            lease_seconds=self.lease_seconds,
            now=now,
        )
        delivered = 0
        retried = 0
        for message in claimed:
            try:
                handler = self.handler_registry.get(message.topic)
                if handler is None:
                    raise OutboxHandlerError(f"unknown outbox topic '{message.topic}'")
                handler.handle(storage=self.storage, message=message)
            except Exception as exc:
                next_attempt_at = self._next_attempt_at(message, now=now)
                self.storage.mark_outbox_retry(
                    outbox_id=message.id,
                    claim_token=message.claim_token,
                    next_attempt_at=next_attempt_at,
                    last_error=str(exc),
                )
                retried += 1
            else:
                self.storage.mark_outbox_delivered(
                    outbox_id=message.id,
                    claim_token=message.claim_token,
                    delivered_at=now,
                )
                delivered += 1
        return WorkerSummaryV1(claimed=len(claimed), delivered=delivered, retried=retried)

    def _next_attempt_at(
        self,
        message: ClaimedOutboxMessage,
        *,
        now: datetime | None,
    ) -> datetime:
        effective_now = message.claimed_at if now is None else now.astimezone(UTC)
        exponent = max(message.attempts - 1, 0)
        delay_seconds = min(self.base_retry_seconds * (2**exponent), self.max_retry_seconds)
        return effective_now + timedelta(seconds=delay_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Process the SkillTrust transactional outbox")
    parser.add_argument("--database-url", default="sqlite+pysqlite:///./.skilltrust/control-plane.db")
    parser.add_argument("--claimant", default="skilltrust-worker")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--lease-seconds", type=int, default=60)
    args = parser.parse_args()

    storage = SkillTrustStorage(args.database_url)
    storage.create_schema()
    worker = OutboxWorker(
        storage=storage,
        claimant=args.claimant,
        lease_seconds=args.lease_seconds,
    )
    try:
        summary = worker.run_once(limit=args.limit)
        print(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
    finally:
        storage.dispose()


def _require_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise OutboxHandlerError(f"outbox payload field '{key}' must be an integer")
    return value


def _require_str(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise OutboxHandlerError(f"outbox payload field '{key}' must be a non-empty string")
    return value


def _require_digest_list(payload: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise OutboxHandlerError(f"outbox payload field '{key}' must be a non-empty list")
    if any(not isinstance(item, str) or not item.startswith("sha256:") for item in value):
        raise OutboxHandlerError(f"outbox payload field '{key}' must contain sha256 digests")
    return tuple(value)


__all__ = [
    "DEFAULT_HANDLER_REGISTRY",
    "ContributionRecordedHandler",
    "OutboxHandler",
    "OutboxHandlerError",
    "OutboxWorker",
    "RevocationRecordedHandler",
    "WorkerSummaryV1",
    "main",
]
