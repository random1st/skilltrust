from __future__ import annotations

from datetime import UTC, datetime, timedelta

from skilltrust.hooks import HookSummary
from skilltrust.models import (
    FileRecord,
    PayloadTier,
    SkillManifestV1,
    SourceRef,
    TrustDomain,
    TrustPolicyV1,
    ValidationResultV1,
    ValidationStatus,
    VerificationAction,
    canonical_json_bytes,
    sha256_digest,
)
from skilltrust.policy import ApprovalRecord, evaluate_policy

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def source(*, commit_sha: str) -> SourceRef:
    return SourceRef(
        provider="github",
        repository_id="R_123",
        clone_url="https://github.com/acme/skills.git",
        commit_sha=commit_sha,
    )


def policy(*, trust_domain: TrustDomain, runtime_adapters: tuple[str, ...] = ()) -> TrustPolicyV1:
    return TrustPolicyV1(
        policy_id=f"{trust_domain.value}-default",
        version=1,
        trust_domain=trust_domain,
        accepted_oidc_issuers=("https://token.actions.githubusercontent.com",),
        accepted_identities=(
            "https://github.com/acme/skills/.github/workflows/release.yml@refs/heads/main",
        ),
        required_validators=("archive-safety",),
        declarative_lease=timedelta(days=7),
        executable_lease=timedelta(hours=24),
        max_offline_lease=timedelta(days=30 if trust_domain is TrustDomain.ENTERPRISE else 7),
        runtime_capability_adapters=runtime_adapters,
    )


def manifest(*, tier: PayloadTier, commit_sha: str) -> SkillManifestV1:
    files = (FileRecord(path="run.py", digest=DIGEST_A, size=1, executable=True),)
    return SkillManifestV1(
        name="safe-skill",
        version="1.0.0",
        payload_tier=tier,
        source=source(commit_sha=commit_sha),
        description="Example",
        entrypoints=("run.py",) if tier is PayloadTier.EXECUTABLE else (),
        files=files if tier is PayloadTier.EXECUTABLE else (),
    )


def approval_for(manifest_value: SkillManifestV1, *, artifact_digest: str) -> ApprovalRecord:
    return ApprovalRecord(
        repository_id=manifest_value.source.repository_id,
        head_sha=manifest_value.source.commit_sha,
        manifest_digest=sha256_digest(canonical_json_bytes(manifest_value)),
        artifact_digest=artifact_digest,
        approver="reviewer@example.test",
        approved_at=datetime.now(UTC),
    )


def validation_result(subject_digest: str) -> ValidationResultV1:
    now = datetime.now(UTC)
    return ValidationResultV1(
        validator="archive-safety",
        validator_version="1",
        subject_digest=subject_digest,
        status=ValidationStatus.PASS,
        code="clean",
        message="No findings",
        evidence=(DIGEST_C,),
        started_at=now,
        completed_at=now,
    )


class SupportingRuntime:
    adapter_id = "sandbox-v1"

    def supports(self, manifest: SkillManifestV1) -> bool:
        return manifest.payload_tier is PayloadTier.EXECUTABLE


class UnsupportedRuntime:
    adapter_id = "sandbox-v1"

    def supports(self, manifest: SkillManifestV1) -> bool:
        del manifest
        return False


def test_stale_approval_is_denied_on_head_change() -> None:
    old_manifest = manifest(tier=PayloadTier.DECLARATIVE, commit_sha="b" * 40)
    updated_manifest = manifest(tier=PayloadTier.DECLARATIVE, commit_sha="c" * 40)
    decision = evaluate_policy(
        manifest=updated_manifest,
        artifact_digest=DIGEST_B,
        policy=policy(trust_domain=TrustDomain.COMMUNITY),
        approval=approval_for(old_manifest, artifact_digest=DIGEST_B),
        validation_results=(validation_result(DIGEST_B),),
    )
    assert decision.action is VerificationAction.DENY
    assert decision.status is ValidationStatus.FAIL
    assert decision.reason_codes == ("approval_stale",)


def test_executable_skill_without_supported_runtime_is_unknown() -> None:
    executable_manifest = manifest(tier=PayloadTier.EXECUTABLE, commit_sha="b" * 40)
    decision = evaluate_policy(
        manifest=executable_manifest,
        artifact_digest=DIGEST_B,
        policy=policy(
            trust_domain=TrustDomain.ENTERPRISE,
            runtime_adapters=("sandbox-v1",),
        ),
        approval=approval_for(executable_manifest, artifact_digest=DIGEST_B),
        validation_results=(validation_result(DIGEST_B),),
        runtime_adapter=UnsupportedRuntime(),
    )
    assert decision.action is VerificationAction.DENY
    assert decision.status is ValidationStatus.UNKNOWN
    assert decision.reason_codes == ("runtime_capability_unsupported",)


def test_allow_decision_uses_bounded_tier_lease() -> None:
    now = datetime(2026, 8, 1, tzinfo=UTC)
    executable_manifest = manifest(tier=PayloadTier.EXECUTABLE, commit_sha="b" * 40)
    decision = evaluate_policy(
        manifest=executable_manifest,
        artifact_digest=DIGEST_B,
        policy=policy(
            trust_domain=TrustDomain.ENTERPRISE,
            runtime_adapters=("sandbox-v1",),
        ),
        approval=approval_for(executable_manifest, artifact_digest=DIGEST_B),
        validation_results=(validation_result(DIGEST_B),),
        runtime_adapter=SupportingRuntime(),
        evaluated_at=now,
    )
    assert decision.action is VerificationAction.ALLOW
    assert decision.status is ValidationStatus.PASS
    assert decision.lease_expires_at == now + timedelta(hours=24)
    assert DIGEST_C in decision.evidence


def test_unknown_required_hook_denies_policy() -> None:
    declarative_manifest = manifest(tier=PayloadTier.DECLARATIVE, commit_sha="b" * 40)
    decision = evaluate_policy(
        manifest=declarative_manifest,
        artifact_digest=DIGEST_B,
        policy=policy(trust_domain=TrustDomain.COMMUNITY),
        approval=approval_for(declarative_manifest, artifact_digest=DIGEST_B),
        validation_results=(validation_result(DIGEST_B),),
        hook_summary=HookSummary(
            results=(),
            status=ValidationStatus.UNKNOWN,
            reason_codes=("hook_sandbox_missing",),
        ),
    )
    assert decision.action is VerificationAction.DENY
    assert decision.status is ValidationStatus.UNKNOWN
    assert decision.reason_codes == ("hook_sandbox_missing",)
