from datetime import UTC, datetime

from skilltrust.attestations import slsa_predicate_from_notarization
from skilltrust.models import (
    NotarizationV1,
    SourceRef,
    TrustDomain,
    ValidationResultV1,
    ValidationStatus,
)


def test_slsa_predicate_binds_source_policy_and_evidence() -> None:
    now = datetime.now(UTC)
    digest = "sha256:" + "a" * 64
    evidence = "sha256:" + "b" * 64
    notarization = NotarizationV1(
        artifact_digest=digest,
        manifest_digest="sha256:" + "c" * 64,
        source=SourceRef(
            provider="github",
            repository_id="R_123",
            clone_url="https://github.com/acme/skills.git",
            commit_sha="d" * 40,
        ),
        trust_domain=TrustDomain.COMMUNITY,
        builder_identity="https://github.com/acme/skills/.github/workflows/build.yml@refs/heads/main",
        validation_results=(
            ValidationResultV1(
                validator="archive-safety",
                validator_version="1",
                subject_digest=digest,
                status=ValidationStatus.PASS,
                code="safe",
                message="Safe archive",
                evidence=(evidence,),
                started_at=now,
                completed_at=now,
            ),
        ),
        signature_bundle_digest="sha256:" + "e" * 64,
        transparency_log_entry="1234",
        issued_at=now,
    )

    predicate = slsa_predicate_from_notarization(
        notarization,
        policy_digest="sha256:" + "f" * 64,
        invocation_id="build-123",
    ).model_dump(mode="json", by_alias=True)

    assert predicate["buildDefinition"]["externalParameters"]["artifactDigest"] == "a" * 64
    assert predicate["buildDefinition"]["internalParameters"]["policyDigest"].startswith("sha256:")
    assert predicate["buildDefinition"]["resolvedDependencies"][0]["digest"] == {
        "gitCommit": "d" * 40
    }
