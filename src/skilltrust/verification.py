"""Fail-closed admission decision over all independent trust layers."""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import Field, model_validator

from skilltrust.models import (
    GitSha,
    NotarizationV1,
    PayloadTier,
    Sha256,
    SkillManifestV1,
    StrictModel,
    TrustDomain,
    TrustPolicyV1,
    ValidationStatus,
    VerificationAction,
    VerificationDecisionV1,
    canonical_json_bytes,
    sha256_digest,
)


class SignatureVerificationV1(StrictModel):
    """Result produced by a Sigstore or pinned private-PKI adapter."""

    subject_digest: Sha256
    trust_domain: TrustDomain
    status: ValidationStatus
    code: str = Field(min_length=1, max_length=128)
    identity: str | None = Field(default=None, max_length=1024)
    oidc_issuer: str | None = Field(default=None, max_length=2048)
    manifest_digest: Sha256 | None = None
    source_commit_sha: GitSha | None = None
    policy_digest: Sha256 | None = None
    evidence: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def pass_requires_identity_and_evidence(self) -> SignatureVerificationV1:
        if self.status is ValidationStatus.PASS:
            if not self.identity or not self.oidc_issuer:
                raise ValueError("PASS signature check requires identity and issuer")
            if not self.manifest_digest or not self.source_commit_sha or not self.policy_digest:
                raise ValueError("PASS signature check requires provenance bindings")
            if not self.evidence:
                raise ValueError("PASS signature check requires immutable evidence")
        return self


class CatalogVerificationV1(StrictModel):
    """Freshness result from a domain-specific TUF client and root."""

    trust_domain: TrustDomain
    artifact_digest: Sha256
    status: ValidationStatus
    code: str = Field(min_length=1, max_length=128)
    checked_at: datetime
    valid_until: datetime
    root_version: int = Field(ge=1)
    timestamp_version: int = Field(ge=1)
    evidence: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def pass_requires_fresh_evidence(self) -> CatalogVerificationV1:
        if self.valid_until <= self.checked_at:
            raise ValueError("catalog valid_until must follow checked_at")
        if self.status is ValidationStatus.PASS and not self.evidence:
            raise ValueError("PASS catalog check requires immutable evidence")
        return self


class VerificationInputV1(StrictModel):
    artifact_digest: Sha256
    manifest: SkillManifestV1
    notarization: NotarizationV1
    policy: TrustPolicyV1
    signature: SignatureVerificationV1
    catalog: CatalogVerificationV1
    revoked_artifacts: frozenset[Sha256] = frozenset()
    runtime_adapter: str | None = None
    evaluated_at: datetime


def _status_for_reasons(definite_failures: list[str], unknowns: list[str]) -> ValidationStatus:
    if definite_failures:
        return ValidationStatus.FAIL
    if unknowns:
        return ValidationStatus.UNKNOWN
    return ValidationStatus.PASS


def verify(input_: VerificationInputV1) -> VerificationDecisionV1:
    """Evaluate every trust layer; no missing or stale evidence can authorize use."""

    failures: list[str] = []
    unknowns: list[str] = []
    evidence: set[str] = set()
    manifest_digest = sha256_digest(canonical_json_bytes(input_.manifest))
    policy_digest = sha256_digest(canonical_json_bytes(input_.policy))

    if input_.artifact_digest != input_.notarization.artifact_digest:
        failures.append("artifact_digest_mismatch")
    if manifest_digest != input_.notarization.manifest_digest:
        failures.append("manifest_digest_mismatch")
    if input_.manifest.source != input_.notarization.source:
        failures.append("source_mismatch")
    if input_.manifest.source.commit_sha != input_.notarization.source.commit_sha:
        failures.append("source_commit_mismatch")
    if input_.policy.trust_domain != input_.notarization.trust_domain:
        failures.append("notarization_cross_domain")

    signature = input_.signature
    if signature.status is ValidationStatus.FAIL:
        failures.append(f"signature:{signature.code}")
    elif signature.status is ValidationStatus.UNKNOWN:
        unknowns.append(f"signature:{signature.code}")
    if signature.subject_digest != input_.artifact_digest:
        failures.append("signature_subject_mismatch")
    if signature.trust_domain != input_.policy.trust_domain:
        failures.append("signature_cross_domain")
    if signature.status is ValidationStatus.PASS:
        if signature.identity not in input_.policy.accepted_identities:
            failures.append("signer_identity_not_authorized")
        if signature.oidc_issuer not in input_.policy.accepted_oidc_issuers:
            failures.append("signer_issuer_not_authorized")
        if signature.identity != input_.notarization.builder_identity:
            failures.append("builder_identity_mismatch")
        if signature.manifest_digest != input_.notarization.manifest_digest:
            failures.append("signature_manifest_mismatch")
        if signature.source_commit_sha != input_.notarization.source.commit_sha:
            failures.append("signature_source_mismatch")
        if signature.policy_digest != policy_digest:
            failures.append("signature_policy_mismatch")
        evidence.update(signature.evidence)

    catalog = input_.catalog
    if catalog.status is ValidationStatus.FAIL:
        failures.append(f"catalog:{catalog.code}")
    elif catalog.status is ValidationStatus.UNKNOWN:
        unknowns.append(f"catalog:{catalog.code}")
    if catalog.artifact_digest != input_.artifact_digest:
        failures.append("catalog_subject_mismatch")
    if catalog.trust_domain != input_.policy.trust_domain:
        failures.append("catalog_cross_domain")
    if catalog.status is ValidationStatus.PASS:
        evidence.update(catalog.evidence)
    if input_.evaluated_at >= catalog.valid_until:
        unknowns.append("catalog_stale")
    if catalog.checked_at > input_.evaluated_at + timedelta(minutes=5):
        failures.append("catalog_check_from_future")

    results_by_validator = {
        result.validator: result for result in input_.notarization.validation_results
    }
    for validator in input_.policy.required_validators:
        result = results_by_validator.get(validator)
        if result is None:
            unknowns.append(f"validator_missing:{validator}")
            continue
        if result.subject_digest != input_.artifact_digest:
            failures.append(f"validator_subject_mismatch:{validator}")
            continue
        if result.status is ValidationStatus.FAIL:
            failures.append(f"validator_failed:{validator}")
        elif result.status is ValidationStatus.UNKNOWN:
            unknowns.append(f"validator_unknown:{validator}")
        else:
            evidence.update(result.evidence)

    if input_.artifact_digest in input_.revoked_artifacts:
        failures.append("artifact_revoked")
    revoked_dependencies = sorted(
        dependency.artifact_digest
        for dependency in input_.manifest.dependencies
        if dependency.artifact_digest in input_.revoked_artifacts
    )
    if revoked_dependencies:
        failures.append("dependency_revoked:" + ",".join(revoked_dependencies))

    if input_.manifest.payload_tier is PayloadTier.EXECUTABLE:
        if input_.runtime_adapter is None:
            failures.append("runtime_adapter_missing")
        elif input_.runtime_adapter not in input_.policy.runtime_capability_adapters:
            failures.append("runtime_adapter_not_authorized")

    if input_.notarization.issued_at > input_.evaluated_at + timedelta(minutes=5):
        failures.append("notarization_from_future")

    lease_duration = (
        input_.policy.executable_lease
        if input_.manifest.payload_tier is PayloadTier.EXECUTABLE
        else input_.policy.declarative_lease
    )
    lease_expires_at = min(catalog.valid_until, catalog.checked_at + lease_duration)
    if input_.evaluated_at >= lease_expires_at:
        unknowns.append("offline_lease_expired")

    status = _status_for_reasons(failures, unknowns)
    if status is ValidationStatus.PASS:
        evidence.add(input_.notarization.signature_bundle_digest)
        evidence.add(policy_digest)
        return VerificationDecisionV1(
            action=VerificationAction.ALLOW,
            status=status,
            artifact_digest=input_.artifact_digest,
            trust_domain=input_.policy.trust_domain,
            policy_digest=policy_digest,
            reason_codes=("all_required_checks_passed",),
            evaluated_at=input_.evaluated_at,
            lease_expires_at=lease_expires_at,
            evidence=tuple(sorted(evidence)),
        )

    return VerificationDecisionV1(
        action=VerificationAction.DENY,
        status=status,
        artifact_digest=input_.artifact_digest,
        trust_domain=input_.policy.trust_domain,
        policy_digest=policy_digest,
        reason_codes=tuple(failures + unknowns),
        evaluated_at=input_.evaluated_at,
        evidence=tuple(sorted(evidence)),
    )
