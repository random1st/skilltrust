"""Policy evaluation helpers for approval binding, leases, and runtime enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from skilltrust.hooks import HookSummary
from skilltrust.models import (
    PayloadTier,
    SkillManifestV1,
    TrustDomain,
    TrustPolicyV1,
    ValidationResultV1,
    ValidationStatus,
    VerificationAction,
    VerificationDecisionV1,
    canonical_json_bytes,
    sha256_digest,
    utc_now,
)


@dataclass(frozen=True)
class ApprovalRecord:
    """Reviewer approval bound to one exact repository head and immutable digests."""

    repository_id: str
    head_sha: str
    manifest_digest: str
    artifact_digest: str
    approver: str
    approved_at: datetime


class RuntimeCapabilityAdapter(Protocol):
    """Runtime adapter contract for executable skills."""

    adapter_id: str

    def supports(self, manifest: SkillManifestV1) -> bool:
        """Return whether the adapter can enforce the manifest's runtime needs."""


def approval_matches(
    approval: ApprovalRecord,
    manifest: SkillManifestV1,
    *,
    manifest_digest: str,
    artifact_digest: str,
) -> bool:
    return (
        approval.repository_id == manifest.source.repository_id
        and approval.head_sha == manifest.source.commit_sha
        and approval.manifest_digest == manifest_digest
        and approval.artifact_digest == artifact_digest
    )


def evaluate_policy(
    *,
    manifest: SkillManifestV1,
    artifact_digest: str,
    policy: TrustPolicyV1,
    approval: ApprovalRecord | None,
    validation_results: tuple[ValidationResultV1, ...],
    runtime_adapter: RuntimeCapabilityAdapter | None = None,
    hook_summary: HookSummary | None = None,
    evaluated_at: datetime | None = None,
    manifest_digest: str | None = None,
) -> VerificationDecisionV1:
    """Evaluate installation/execution policy using fail-closed rules."""

    now = utc_now() if evaluated_at is None else evaluated_at
    subject_manifest_digest = (
        sha256_digest(canonical_json_bytes(manifest))
        if manifest_digest is None
        else manifest_digest
    )
    policy_digest = sha256_digest(canonical_json_bytes(policy))

    approval_status, approval_reason = _approval_gate(
        approval=approval,
        manifest=manifest,
        manifest_digest=subject_manifest_digest,
        artifact_digest=artifact_digest,
    )
    if approval_status is not ValidationStatus.PASS:
        return _deny_decision(
            artifact_digest=artifact_digest,
            trust_domain=policy.trust_domain,
            policy_digest=policy_digest,
            status=approval_status,
            reason_codes=(approval_reason,),
            evaluated_at=now,
        )

    validator_status, validator_reasons = _validator_gate(policy, validation_results)
    if validator_status is not ValidationStatus.PASS:
        return _deny_decision(
            artifact_digest=artifact_digest,
            trust_domain=policy.trust_domain,
            policy_digest=policy_digest,
            status=validator_status,
            reason_codes=validator_reasons,
            evaluated_at=now,
        )

    if hook_summary is not None and hook_summary.status is not ValidationStatus.PASS:
        return _deny_decision(
            artifact_digest=artifact_digest,
            trust_domain=policy.trust_domain,
            policy_digest=policy_digest,
            status=hook_summary.status,
            reason_codes=hook_summary.reason_codes,
            evaluated_at=now,
        )

    runtime_status, runtime_reason = _runtime_gate(
        manifest=manifest,
        policy=policy,
        runtime_adapter=runtime_adapter,
    )
    if runtime_status is not ValidationStatus.PASS:
        return _deny_decision(
            artifact_digest=artifact_digest,
            trust_domain=policy.trust_domain,
            policy_digest=policy_digest,
            status=runtime_status,
            reason_codes=(runtime_reason,),
            evaluated_at=now,
        )

    evidence = _decision_evidence(
        manifest_digest=subject_manifest_digest,
        artifact_digest=artifact_digest,
        validation_results=validation_results,
    )
    return VerificationDecisionV1(
        action=VerificationAction.ALLOW,
        status=ValidationStatus.PASS,
        artifact_digest=artifact_digest,
        trust_domain=policy.trust_domain,
        policy_digest=policy_digest,
        reason_codes=("policy_passed",),
        evaluated_at=now,
        lease_expires_at=now + _lease_for(manifest.payload_tier, policy),
        evidence=evidence,
    )


def _approval_gate(
    *,
    approval: ApprovalRecord | None,
    manifest: SkillManifestV1,
    manifest_digest: str,
    artifact_digest: str,
) -> tuple[ValidationStatus, str]:
    if approval is None:
        return ValidationStatus.UNKNOWN, "approval_missing"
    if approval.repository_id != manifest.source.repository_id:
        return ValidationStatus.FAIL, "approval_repository_mismatch"
    if approval.head_sha != manifest.source.commit_sha:
        return ValidationStatus.FAIL, "approval_stale"
    if approval.manifest_digest != manifest_digest:
        return ValidationStatus.FAIL, "approval_manifest_mismatch"
    if approval.artifact_digest != artifact_digest:
        return ValidationStatus.FAIL, "approval_artifact_mismatch"
    return ValidationStatus.PASS, "approval_bound"


def _validator_gate(
    policy: TrustPolicyV1, results: tuple[ValidationResultV1, ...]
) -> tuple[ValidationStatus, tuple[str, ...]]:
    statuses_by_validator: dict[str, tuple[ValidationStatus, ...]] = {}
    for result in results:
        statuses_by_validator.setdefault(result.validator, ())
        statuses_by_validator[result.validator] = statuses_by_validator[result.validator] + (
            result.status,
        )

    reasons: list[str] = []
    for validator in policy.required_validators:
        statuses = statuses_by_validator.get(validator)
        if not statuses:
            reasons.append(f"validator_missing:{validator}")
            continue
        if any(status is ValidationStatus.FAIL for status in statuses):
            reasons.append(f"validator_failed:{validator}")
            continue
        if any(status is ValidationStatus.UNKNOWN for status in statuses):
            reasons.append(f"validator_unknown:{validator}")
    if not reasons:
        return ValidationStatus.PASS, ()
    if any(reason.startswith("validator_failed:") for reason in reasons):
        return ValidationStatus.FAIL, tuple(reasons)
    return ValidationStatus.UNKNOWN, tuple(reasons)


def _runtime_gate(
    *,
    manifest: SkillManifestV1,
    policy: TrustPolicyV1,
    runtime_adapter: RuntimeCapabilityAdapter | None,
) -> tuple[ValidationStatus, str]:
    if manifest.payload_tier is not PayloadTier.EXECUTABLE:
        return ValidationStatus.PASS, "runtime_not_required"
    if runtime_adapter is None:
        return ValidationStatus.UNKNOWN, "runtime_adapter_required"
    if runtime_adapter.adapter_id not in policy.runtime_capability_adapters:
        return ValidationStatus.UNKNOWN, "runtime_adapter_not_allowed"
    if not runtime_adapter.supports(manifest):
        return ValidationStatus.UNKNOWN, "runtime_capability_unsupported"
    return ValidationStatus.PASS, "runtime_supported"


def _decision_evidence(
    *,
    manifest_digest: str,
    artifact_digest: str,
    validation_results: tuple[ValidationResultV1, ...],
) -> tuple[str, ...]:
    evidence = {manifest_digest, artifact_digest}
    for result in validation_results:
        evidence.update(result.evidence)
    return tuple(sorted(evidence))


def _deny_decision(
    *,
    artifact_digest: str,
    trust_domain: TrustDomain,
    policy_digest: str,
    status: ValidationStatus,
    reason_codes: tuple[str, ...],
    evaluated_at: datetime,
) -> VerificationDecisionV1:
    return VerificationDecisionV1(
        action=VerificationAction.DENY,
        status=status,
        artifact_digest=artifact_digest,
        trust_domain=trust_domain,
        policy_digest=policy_digest,
        reason_codes=reason_codes,
        evaluated_at=evaluated_at,
    )


def _lease_for(payload_tier: PayloadTier, policy: TrustPolicyV1) -> timedelta:
    if payload_tier is PayloadTier.EXECUTABLE:
        return policy.executable_lease
    return policy.declarative_lease


__all__ = [
    "ApprovalRecord",
    "RuntimeCapabilityAdapter",
    "approval_matches",
    "evaluate_policy",
]
