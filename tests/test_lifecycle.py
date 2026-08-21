from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from skilltrust.lifecycle import (
    LifecycleTransitionError,
    RevocationIndex,
    emergency_revoke,
    transition_lifecycle,
)
from skilltrust.models import (
    LifecycleState,
    RevocationV1,
    TrustDomain,
    ValidationStatus,
    VerificationAction,
    VerificationDecisionV1,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


def allow_decision(artifact_digest: str) -> VerificationDecisionV1:
    now = datetime.now(UTC)
    return VerificationDecisionV1(
        action=VerificationAction.ALLOW,
        status=ValidationStatus.PASS,
        artifact_digest=artifact_digest,
        trust_domain=TrustDomain.ENTERPRISE,
        policy_digest=DIGEST_D,
        reason_codes=("policy_passed",),
        evaluated_at=now,
        lease_expires_at=now,
        evidence=(DIGEST_A,),
    )


def revocation(*artifact_digests: str) -> RevocationV1:
    now = datetime.now(UTC)
    return RevocationV1(
        revocation_id="rev-1",
        trust_domain=TrustDomain.ENTERPRISE,
        artifact_digests=artifact_digests,
        reason_code="compromised",
        reason="artifact was compromised",
        effective_at=now,
        issued_at=now,
        issuer="spiffe://example.internal/security",
        signature_bundle_digest=DIGEST_D,
    )


def test_invalid_transition_is_rejected() -> None:
    with pytest.raises(LifecycleTransitionError, match="invalid lifecycle transition"):
        transition_lifecycle(LifecycleState.REVIEWED, LifecycleState.UNTRUSTED)


@pytest.mark.parametrize(
    "state",
    [
        LifecycleState.UNTRUSTED,
        LifecycleState.REVIEWED,
        LifecycleState.NOTARIZED,
        LifecycleState.PUBLISHED,
    ],
)
def test_emergency_revoke_works_from_any_state(state: LifecycleState) -> None:
    assert emergency_revoke(state) is LifecycleState.REVOKED


def test_cached_revocation_overrides_prior_allow() -> None:
    index = RevocationIndex()
    index.add_revocation(revocation(DIGEST_A))
    decision = index.enforce_cached_decision(allow_decision(DIGEST_A))
    assert decision.action is VerificationAction.DENY
    assert decision.status is ValidationStatus.FAIL
    assert decision.reason_codes == ("artifact_revoked", "compromised")


def test_transitive_dependency_revocation_denies_parent_artifact() -> None:
    index = RevocationIndex()
    index.add_dependencies(DIGEST_A, (DIGEST_B,))
    index.add_dependencies(DIGEST_B, (DIGEST_C,))
    index.add_revocation(revocation(DIGEST_C))

    assert index.is_revoked(DIGEST_A, TrustDomain.ENTERPRISE) is True
    decision = index.enforce_cached_decision(allow_decision(DIGEST_A))
    assert decision.action is VerificationAction.DENY
    assert decision.reason_codes == ("dependency_revoked", "compromised")


def test_cached_allow_is_invalidated_when_lease_expires() -> None:
    now = datetime.now(UTC)
    decision = VerificationDecisionV1(
        action=VerificationAction.ALLOW,
        status=ValidationStatus.PASS,
        artifact_digest=DIGEST_A,
        trust_domain=TrustDomain.ENTERPRISE,
        policy_digest=DIGEST_D,
        reason_codes=("verified",),
        evaluated_at=now - timedelta(hours=2),
        lease_expires_at=now - timedelta(seconds=1),
        evidence=(DIGEST_B,),
    )
    enforced = RevocationIndex().enforce_cached_decision(decision, evaluated_at=now)
    assert enforced.action is VerificationAction.DENY
    assert enforced.status is ValidationStatus.UNKNOWN
    assert enforced.reason_codes == ("cached_lease_expired",)
