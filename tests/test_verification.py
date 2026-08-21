from datetime import UTC, datetime, timedelta

from skilltrust.models import (
    FileRecord,
    NotarizationV1,
    PayloadTier,
    SkillDependency,
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
from skilltrust.verification import (
    CatalogVerificationV1,
    SignatureVerificationV1,
    VerificationInputV1,
    verify,
)

ARTIFACT = "sha256:" + "a" * 64
EVIDENCE = "sha256:" + "e" * 64
IDENTITY = "https://github.com/acme/skills/.github/workflows/build.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def make_input(
    *,
    tier: PayloadTier = PayloadTier.DECLARATIVE,
    revoked: frozenset[str] = frozenset(),
    dependencies: tuple[SkillDependency, ...] = (),
    signature_status: ValidationStatus = ValidationStatus.PASS,
    runtime_adapter: str | None = None,
    catalog_age: timedelta = timedelta(0),
) -> VerificationInputV1:
    now = datetime.now(UTC)
    source = SourceRef(
        provider="github",
        repository_id="R_123",
        clone_url="https://github.com/acme/skills.git",
        commit_sha="b" * 40,
    )
    files = (FileRecord(path="run.py", digest="sha256:" + "c" * 64, size=1),)
    manifest = SkillManifestV1(
        name="safe-skill",
        version="1.0.0",
        payload_tier=tier,
        source=source,
        description="A safe example",
        entrypoints=("run.py",) if tier is PayloadTier.EXECUTABLE else (),
        files=files,
        dependencies=dependencies,
    )
    validator = ValidationResultV1(
        validator="archive-safety",
        validator_version="1",
        subject_digest=ARTIFACT,
        status=ValidationStatus.PASS,
        code="safe",
        message="Safe archive",
        evidence=(EVIDENCE,),
        started_at=now,
        completed_at=now,
    )
    notarization = NotarizationV1(
        artifact_digest=ARTIFACT,
        manifest_digest=sha256_digest(canonical_json_bytes(manifest)),
        source=source,
        trust_domain=TrustDomain.COMMUNITY,
        builder_identity=IDENTITY,
        validation_results=(validator,),
        signature_bundle_digest="sha256:" + "d" * 64,
        transparency_log_entry="1234",
        issued_at=now,
    )
    policy = TrustPolicyV1(
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
    checked_at = now - catalog_age
    return VerificationInputV1(
        artifact_digest=ARTIFACT,
        manifest=manifest,
        notarization=notarization,
        policy=policy,
        signature=SignatureVerificationV1(
            subject_digest=ARTIFACT,
            trust_domain=TrustDomain.COMMUNITY,
            status=signature_status,
            code="verified" if signature_status is ValidationStatus.PASS else "unavailable",
            identity=IDENTITY if signature_status is ValidationStatus.PASS else None,
            oidc_issuer=ISSUER if signature_status is ValidationStatus.PASS else None,
            manifest_digest=(
                notarization.manifest_digest if signature_status is ValidationStatus.PASS else None
            ),
            source_commit_sha=(
                notarization.source.commit_sha
                if signature_status is ValidationStatus.PASS
                else None
            ),
            policy_digest=(
                sha256_digest(canonical_json_bytes(policy))
                if signature_status is ValidationStatus.PASS
                else None
            ),
            evidence=(EVIDENCE,) if signature_status is ValidationStatus.PASS else (),
        ),
        catalog=CatalogVerificationV1(
            trust_domain=TrustDomain.COMMUNITY,
            artifact_digest=ARTIFACT,
            status=ValidationStatus.PASS,
            code="fresh",
            checked_at=checked_at,
            valid_until=checked_at + timedelta(days=8),
            root_version=1,
            timestamp_version=2,
            evidence=("sha256:" + "f" * 64,),
        ),
        revoked_artifacts=revoked,
        runtime_adapter=runtime_adapter,
        evaluated_at=now,
    )


def test_all_layers_allow_with_bounded_lease() -> None:
    decision = verify(make_input())
    assert decision.action is VerificationAction.ALLOW
    assert decision.status is ValidationStatus.PASS
    assert decision.lease_expires_at is not None


def test_unknown_signature_is_deny_not_pass() -> None:
    decision = verify(make_input(signature_status=ValidationStatus.UNKNOWN))
    assert decision.action is VerificationAction.DENY
    assert decision.status is ValidationStatus.UNKNOWN
    assert "signature:unavailable" in decision.reason_codes


def test_revoked_transitive_dependency_is_denied() -> None:
    revoked_digest = "sha256:" + "9" * 64
    dependency = SkillDependency(name="dependency", version="1", artifact_digest=revoked_digest)
    decision = verify(make_input(dependencies=(dependency,), revoked=frozenset({revoked_digest})))
    assert decision.status is ValidationStatus.FAIL
    assert any(reason.startswith("dependency_revoked:") for reason in decision.reason_codes)


def test_executable_requires_authorized_runtime_adapter() -> None:
    missing = verify(make_input(tier=PayloadTier.EXECUTABLE))
    unauthorized = verify(
        make_input(tier=PayloadTier.EXECUTABLE, runtime_adapter="unknown-sandbox")
    )
    allowed = verify(make_input(tier=PayloadTier.EXECUTABLE, runtime_adapter="sandbox-v1"))
    assert "runtime_adapter_missing" in missing.reason_codes
    assert "runtime_adapter_not_authorized" in unauthorized.reason_codes
    assert allowed.action is VerificationAction.ALLOW


def test_expired_offline_lease_is_unknown_and_denied() -> None:
    decision = verify(make_input(catalog_age=timedelta(days=7, seconds=1)))
    assert decision.action is VerificationAction.DENY
    assert decision.status is ValidationStatus.UNKNOWN
    assert "offline_lease_expired" in decision.reason_codes


def test_manifest_tamper_is_denied() -> None:
    input_ = make_input()
    tampered = input_.model_copy(
        update={"manifest": input_.manifest.model_copy(update={"description": "tampered"})}
    )
    decision = verify(tampered)
    assert decision.status is ValidationStatus.FAIL
    assert "manifest_digest_mismatch" in decision.reason_codes


def test_cross_domain_signature_and_forged_builder_are_denied() -> None:
    input_ = make_input()
    wrong_domain = input_.model_copy(
        update={
            "signature": input_.signature.model_copy(
                update={"trust_domain": TrustDomain.ENTERPRISE}
            )
        }
    )
    forged_builder = input_.model_copy(
        update={
            "notarization": input_.notarization.model_copy(
                update={"builder_identity": "spiffe://attacker.invalid/notary"}
            )
        }
    )
    assert "signature_cross_domain" in verify(wrong_domain).reason_codes
    assert "builder_identity_mismatch" in verify(forged_builder).reason_codes
