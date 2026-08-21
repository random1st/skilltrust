from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from skilltrust.models import (
    FileRecord,
    PayloadTier,
    SkillManifestV1,
    SourceRef,
    TrustDomain,
    TrustPolicyV1,
    ValidationResultV1,
    ValidationStatus,
    canonical_json_bytes,
    sha256_digest,
)

DIGEST = "sha256:" + "a" * 64


def source() -> SourceRef:
    return SourceRef(
        provider="github",
        repository_id="R_123",
        clone_url="https://github.com/acme/skills.git",
        commit_sha="b" * 40,
    )


def test_executable_manifest_requires_existing_entrypoint() -> None:
    with pytest.raises(ValidationError, match="entrypoints are absent"):
        SkillManifestV1(
            name="safe-skill",
            version="1.0.0",
            payload_tier=PayloadTier.EXECUTABLE,
            source=source(),
            description="Example",
            entrypoints=("run.py",),
        )

    manifest = SkillManifestV1(
        name="safe-skill",
        version="1.0.0",
        payload_tier=PayloadTier.EXECUTABLE,
        source=source(),
        description="Example",
        entrypoints=("run.py",),
        files=(FileRecord(path="run.py", digest=DIGEST, size=1, executable=True),),
    )
    assert manifest.entrypoints == ("run.py",)


def test_pass_validation_requires_immutable_evidence() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="PASS requires immutable evidence"):
        ValidationResultV1(
            validator="scanner",
            validator_version="1",
            subject_digest=DIGEST,
            status=ValidationStatus.PASS,
            code="clean",
            message="No findings",
            started_at=now,
            completed_at=now,
        )


def test_community_lease_caps_are_enforced() -> None:
    with pytest.raises(ValidationError, match="cannot exceed 24 hours"):
        TrustPolicyV1(
            policy_id="community-default",
            version=1,
            trust_domain=TrustDomain.COMMUNITY,
            accepted_oidc_issuers=("https://token.actions.githubusercontent.com",),
            accepted_identities=(
                "https://github.com/acme/skills/.github/workflows/release.yml@refs/heads/main",
            ),
            required_validators=("archive-safety",),
            declarative_lease=timedelta(days=7),
            executable_lease=timedelta(hours=25),
            max_offline_lease=timedelta(days=7),
        )


def test_canonical_json_digest_is_order_independent() -> None:
    left = canonical_json_bytes({"b": 2, "a": 1})
    right = canonical_json_bytes({"a": 1, "b": 2})
    assert left == right == b'{"a":1,"b":2}'
    assert sha256_digest(left).startswith("sha256:")
