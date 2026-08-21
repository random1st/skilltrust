"""Lifecycle transitions and revocation-aware authorization invalidation."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from skilltrust.models import (
    LifecycleState,
    RevocationV1,
    SkillManifestV1,
    TrustDomain,
    ValidationStatus,
    VerificationAction,
    VerificationDecisionV1,
    utc_now,
)

_FORWARD_TRANSITIONS: dict[LifecycleState, LifecycleState] = {
    LifecycleState.UNTRUSTED: LifecycleState.REVIEWED,
    LifecycleState.REVIEWED: LifecycleState.NOTARIZED,
    LifecycleState.NOTARIZED: LifecycleState.PUBLISHED,
}


class LifecycleTransitionError(ValueError):
    """Raised when a lifecycle transition violates the monotonic state machine."""


def transition_lifecycle(current: LifecycleState, target: LifecycleState) -> LifecycleState:
    """Apply the monotonic lifecycle rules with emergency revocation from any state."""

    if current is target:
        return current
    if target is LifecycleState.REVOKED:
        return LifecycleState.REVOKED
    if current is LifecycleState.REVOKED:
        raise LifecycleTransitionError("revoked artifacts cannot transition to another state")
    expected = _FORWARD_TRANSITIONS.get(current)
    if expected is target:
        return target
    raise LifecycleTransitionError(
        f"invalid lifecycle transition: {current.value} -> {target.value}"
    )


def emergency_revoke(_: LifecycleState) -> LifecycleState:
    """Force revocation regardless of the previous state."""

    return LifecycleState.REVOKED


advance_lifecycle = transition_lifecycle


class RevocationIndex:
    """In-memory revocation and dependency graph for fail-closed checks."""

    def __init__(self) -> None:
        self._dependency_graph: dict[str, tuple[str, ...]] = {}
        self._revocations: dict[TrustDomain, dict[str, RevocationV1]] = {
            TrustDomain.COMMUNITY: {},
            TrustDomain.ENTERPRISE: {},
        }

    def add_manifest(self, artifact_digest: str, manifest: SkillManifestV1) -> None:
        self._dependency_graph[artifact_digest] = tuple(
            dependency.artifact_digest for dependency in manifest.dependencies
        )

    def add_dependencies(self, artifact_digest: str, dependency_digests: Iterable[str]) -> None:
        self._dependency_graph[artifact_digest] = tuple(dependency_digests)

    def add_revocation(self, revocation: RevocationV1) -> None:
        revoked = self._revocations[revocation.trust_domain]
        for artifact_digest in revocation.artifact_digests:
            revoked[artifact_digest] = revocation

    def resolve_revocation(
        self, artifact_digest: str, trust_domain: TrustDomain
    ) -> tuple[str, RevocationV1] | None:
        revoked = self._revocations[trust_domain]
        stack = [artifact_digest]
        seen: set[str] = set()
        while stack:
            candidate = stack.pop()
            if candidate in seen:
                continue
            seen.add(candidate)
            revocation = revoked.get(candidate)
            if revocation is not None:
                return candidate, revocation
            stack.extend(self._dependency_graph.get(candidate, ()))
        return None

    def is_revoked(self, artifact_digest: str, trust_domain: TrustDomain) -> bool:
        return self.resolve_revocation(artifact_digest, trust_domain) is not None

    def enforce_cached_decision(
        self,
        decision: VerificationDecisionV1,
        *,
        evaluated_at: datetime | None = None,
    ) -> VerificationDecisionV1:
        now = utc_now() if evaluated_at is None else evaluated_at
        if decision.action is VerificationAction.DENY:
            return decision
        resolved = self.resolve_revocation(decision.artifact_digest, decision.trust_domain)
        if resolved is None:
            if decision.lease_expires_at is not None and now < decision.lease_expires_at:
                return decision
            return VerificationDecisionV1(
                action=VerificationAction.DENY,
                status=ValidationStatus.UNKNOWN,
                artifact_digest=decision.artifact_digest,
                trust_domain=decision.trust_domain,
                policy_digest=decision.policy_digest,
                reason_codes=("cached_lease_expired",),
                evaluated_at=now,
                evidence=decision.evidence,
            )
        revoked_digest, revocation = resolved
        reason_code = (
            "artifact_revoked"
            if revoked_digest == decision.artifact_digest
            else "dependency_revoked"
        )
        return VerificationDecisionV1(
            action=VerificationAction.DENY,
            status=ValidationStatus.FAIL,
            artifact_digest=decision.artifact_digest,
            trust_domain=decision.trust_domain,
            policy_digest=decision.policy_digest,
            reason_codes=(reason_code, revocation.reason_code),
            evaluated_at=now,
            evidence=(revocation.signature_bundle_digest,),
        )


__all__ = [
    "LifecycleTransitionError",
    "RevocationIndex",
    "advance_lifecycle",
    "emergency_revoke",
    "transition_lifecycle",
]
