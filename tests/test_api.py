from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from skilltrust.api import Authorizer, Principal, create_app
from skilltrust.models import (
    ContributionRequestV1,
    FileRecord,
    NotarizationV1,
    SkillManifestV1,
    SourceRef,
    TrustDomain,
    TrustPolicyV1,
    ValidationResultV1,
    ValidationStatus,
    canonical_json_bytes,
    sha256_digest,
)
from skilltrust.service import SkillTrustService
from skilltrust.storage import SkillTrustStorage
from skilltrust.verification import (
    CatalogVerificationV1,
    SignatureVerificationV1,
    VerificationInputV1,
)

ARTIFACT_DIGEST = "sha256:" + "a" * 64
EVIDENCE_DIGEST = "sha256:" + "e" * 64
IDENTITY = "https://github.com/acme/skills/.github/workflows/build.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


class AllowAllAuthorizer(Authorizer):
    def authorize(self, principal: Principal, action: str) -> bool:
        del principal, action
        return True


class StaticVerificationProvider:
    def __init__(self, input_: VerificationInputV1) -> None:
        self._input = input_

    def build_input(
        self,
        *,
        artifact_digest: str,
        trust_policy: TrustPolicyV1,
        evaluated_at: datetime,
    ) -> VerificationInputV1:
        assert artifact_digest == self._input.artifact_digest
        assert trust_policy == self._input.policy
        return self._input.model_copy(update={"evaluated_at": evaluated_at})


@pytest.fixture()
def storage(tmp_path: Path) -> SkillTrustStorage:
    database_path = tmp_path / "skilltrust.db"
    instance = SkillTrustStorage(f"sqlite+pysqlite:///{database_path}")
    instance.create_schema()
    try:
        yield instance
    finally:
        instance.dispose()


def test_mutations_are_denied_by_default(storage: SkillTrustStorage) -> None:
    policy = trust_policy()
    app = create_app(
        storage=storage,
        service=SkillTrustService(storage=storage, trust_policies={policy.trust_domain: policy}),
    )

    response = asyncio.run(
        _post(
            app,
            "/v1/contributions",
            json=contribution_payload(),
            headers={"x-principal": "admin@example.com"},
        )
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_denied"


def test_verification_returns_503_unknown_without_external_context(
    storage: SkillTrustStorage,
) -> None:
    policy = trust_policy()
    app = create_app(
        storage=storage,
        service=SkillTrustService(storage=storage, trust_policies={policy.trust_domain: policy}),
        authorizer=AllowAllAuthorizer(),
    )

    response = asyncio.run(
        _post(
            app,
            "/v1/verifications",
            json={"artifact_digest": ARTIFACT_DIGEST, "trust_domain": "community"},
        )
    )

    assert response.status_code == 503
    payload = response.json()
    assert payload["decision"]["status"] == "UNKNOWN"
    assert payload["error_code"] == "verification_evidence_unavailable"


def test_contribution_and_audit_round_trip(storage: SkillTrustStorage) -> None:
    policy = trust_policy()
    provider = StaticVerificationProvider(verification_input(policy=policy))
    service = SkillTrustService(
        storage=storage,
        trust_policies={policy.trust_domain: policy},
        verification_context_provider=provider,
    )
    app = create_app(
        storage=storage,
        service=service,
        authorizer=AllowAllAuthorizer(),
        request_body_limit=4096,
    )

    contribution = asyncio.run(_post(app, "/v1/contributions", json=contribution_payload()))
    verification = asyncio.run(
        _post(
            app,
            "/v1/verifications",
            json={"artifact_digest": ARTIFACT_DIGEST, "trust_domain": "community"},
        )
    )
    audit = asyncio.run(_get(app, f"/v1/audit/artifacts/community/{ARTIFACT_DIGEST}"))

    assert contribution.status_code == 202
    assert verification.status_code == 200
    audit_payload = audit.json()
    assert audit.status_code == 200
    assert audit_payload["latest_decisions"][0]["status"] == "PASS"


def test_request_body_limit_is_enforced(storage: SkillTrustStorage) -> None:
    policy = trust_policy()
    app = create_app(
        storage=storage,
        service=SkillTrustService(storage=storage, trust_policies={policy.trust_domain: policy}),
        authorizer=AllowAllAuthorizer(),
        request_body_limit=64,
    )

    response = asyncio.run(_post(app, "/v1/contributions", content=b"x" * 65))

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_body_too_large"


async def _post(app: FastAPI, path: str, **kwargs: object) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        return await client.post(path, **kwargs)


async def _get(app: FastAPI, path: str) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        return await client.get(path)


def contribution_payload() -> dict[str, object]:
    return ContributionRequestV1(
        request_id="req-1",
        source=SourceRef(
            provider="github",
            repository_id="R_123",
            clone_url="https://github.com/acme/skills.git",
            commit_sha="b" * 40,
            contribution_id="pr-7",
        ),
        manifest_digest=ARTIFACT_DIGEST,
        requested_trust_domain=TrustDomain.COMMUNITY,
        requested_by="review-bot",
        created_at=datetime.now(UTC),
        approval_subjects=("policy-review",),
    ).model_dump(mode="json")


def trust_policy() -> TrustPolicyV1:
    return TrustPolicyV1(
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


def verification_input(*, policy: TrustPolicyV1) -> VerificationInputV1:
    now = datetime.now(UTC)
    source = SourceRef(
        provider="github",
        repository_id="R_123",
        clone_url="https://github.com/acme/skills.git",
        commit_sha="b" * 40,
    )
    manifest = SkillManifestV1(
        name="safe-skill",
        version="1.0.0",
        payload_tier="declarative",
        source=source,
        description="A safe example",
        files=(FileRecord(path="SKILL.md", digest="sha256:" + "c" * 64, size=9),),
    )
    manifest_digest = sha256_digest(canonical_json_bytes(manifest))
    policy_digest = sha256_digest(canonical_json_bytes(policy))
    validator = ValidationResultV1(
        validator="archive-safety",
        validator_version="1",
        subject_digest=ARTIFACT_DIGEST,
        status=ValidationStatus.PASS,
        code="safe",
        message="Safe archive",
        evidence=(EVIDENCE_DIGEST,),
        started_at=now,
        completed_at=now,
    )
    notarization = NotarizationV1(
        artifact_digest=ARTIFACT_DIGEST,
        manifest_digest=manifest_digest,
        source=source,
        trust_domain=TrustDomain.COMMUNITY,
        builder_identity=IDENTITY,
        validation_results=(validator,),
        signature_bundle_digest="sha256:" + "d" * 64,
        transparency_log_entry="rekor-entry",
        issued_at=now,
    )
    return VerificationInputV1(
        artifact_digest=ARTIFACT_DIGEST,
        manifest=manifest,
        notarization=notarization,
        policy=policy,
        signature=SignatureVerificationV1(
            subject_digest=ARTIFACT_DIGEST,
            trust_domain=TrustDomain.COMMUNITY,
            status=ValidationStatus.PASS,
            code="sigstore_identity_verified",
            identity=IDENTITY,
            oidc_issuer=ISSUER,
            manifest_digest=manifest_digest,
            source_commit_sha=source.commit_sha,
            policy_digest=policy_digest,
            evidence=(EVIDENCE_DIGEST,),
        ),
        catalog=CatalogVerificationV1(
            trust_domain=TrustDomain.COMMUNITY,
            artifact_digest=ARTIFACT_DIGEST,
            status=ValidationStatus.PASS,
            code="tuf_target_verified",
            checked_at=now,
            valid_until=now + timedelta(days=1),
            root_version=1,
            timestamp_version=2,
            evidence=("sha256:" + "f" * 64,),
        ),
        evaluated_at=now,
    )
