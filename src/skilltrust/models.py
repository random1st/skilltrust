"""Strict, versioned domain contracts shared by the CLI, API, and workers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
GitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40,64}$")]
SkillName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$"),
]


class StrictModel(BaseModel):
    """Base class that rejects forward-incompatible or misspelled fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrustDomain(StrEnum):
    COMMUNITY = "community"
    ENTERPRISE = "enterprise"


class PayloadTier(StrEnum):
    DECLARATIVE = "declarative"
    EXECUTABLE = "executable"


class ValidationStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 -- validation state, not a credential
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class VerificationAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class LifecycleState(StrEnum):
    UNTRUSTED = "untrusted"
    REVIEWED = "reviewed"
    NOTARIZED = "notarized"
    PUBLISHED = "published"
    REVOKED = "revoked"


class SourceRef(StrictModel):
    provider: Literal["github", "azure-devops", "generic-git"]
    repository_id: str = Field(min_length=1, max_length=512)
    clone_url: str = Field(min_length=1, max_length=2048)
    commit_sha: GitSha
    ref: str | None = Field(default=None, max_length=512)
    contribution_id: str | None = Field(default=None, max_length=256)


class FileRecord(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    digest: Sha256
    size: int = Field(ge=0)
    executable: bool = False


class CapabilityRequest(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    justification: str = Field(min_length=1, max_length=2000)
    required: bool = True


class SkillDependency(StrictModel):
    name: SkillName
    version: str = Field(min_length=1, max_length=128)
    artifact_digest: Sha256


class SkillSourceV1(StrictModel):
    """Contributor-authored declaration; trusted source identity is injected by the builder."""

    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["SkillSource"] = "SkillSource"
    name: SkillName
    version: str = Field(min_length=1, max_length=128)
    payload_tier: PayloadTier
    description: str = Field(min_length=1, max_length=4000)
    entrypoints: tuple[str, ...] = ()
    capabilities: tuple[CapabilityRequest, ...] = ()
    dependencies: tuple[SkillDependency, ...] = ()
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def executable_source_requires_entrypoint(self) -> SkillSourceV1:
        if self.payload_tier is PayloadTier.EXECUTABLE and not self.entrypoints:
            raise ValueError("executable skills require at least one entrypoint")
        return self


class SkillManifestV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["SkillManifest"] = "SkillManifest"
    name: SkillName
    version: str = Field(min_length=1, max_length=128)
    payload_tier: PayloadTier
    source: SourceRef
    description: str = Field(min_length=1, max_length=4000)
    entrypoints: tuple[str, ...] = ()
    files: tuple[FileRecord, ...] = ()
    capabilities: tuple[CapabilityRequest, ...] = ()
    dependencies: tuple[SkillDependency, ...] = ()
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def executable_requires_entrypoint(self) -> SkillManifestV1:
        if self.payload_tier is PayloadTier.EXECUTABLE and not self.entrypoints:
            raise ValueError("executable skills require at least one entrypoint")
        file_paths = {record.path for record in self.files}
        missing = [path for path in self.entrypoints if path not in file_paths]
        if missing:
            raise ValueError(f"entrypoints are absent from files: {', '.join(missing)}")
        return self


class ContributionRequestV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["ContributionRequest"] = "ContributionRequest"
    request_id: str = Field(min_length=1, max_length=256)
    source: SourceRef
    manifest_digest: Sha256
    requested_trust_domain: TrustDomain
    requested_by: str = Field(min_length=1, max_length=512)
    created_at: datetime
    approval_subjects: tuple[str, ...] = ()


class ValidationResultV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["ValidationResult"] = "ValidationResult"
    validator: str = Field(min_length=1, max_length=256)
    validator_version: str = Field(min_length=1, max_length=128)
    subject_digest: Sha256
    status: ValidationStatus
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4000)
    evidence: tuple[Sha256, ...] = ()
    started_at: datetime
    completed_at: datetime

    @model_validator(mode="after")
    def validate_result(self) -> ValidationResultV1:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        if self.status is ValidationStatus.PASS and not self.evidence:
            raise ValueError("PASS requires immutable evidence")
        return self


class NotarizationV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["Notarization"] = "Notarization"
    statement_type: Literal["https://in-toto.io/Statement/v1"] = "https://in-toto.io/Statement/v1"
    predicate_type: Literal["https://skilltrust.dev/Notarization/v1"] = (
        "https://skilltrust.dev/Notarization/v1"
    )
    artifact_digest: Sha256
    manifest_digest: Sha256
    source: SourceRef
    trust_domain: TrustDomain
    builder_identity: str = Field(min_length=1, max_length=1024)
    validation_results: tuple[ValidationResultV1, ...]
    signature_bundle_digest: Sha256
    transparency_log_entry: str | None = Field(default=None, max_length=2048)
    issued_at: datetime

    @model_validator(mode="after")
    def all_results_match_and_pass(self) -> NotarizationV1:
        if not self.validation_results:
            raise ValueError("notarization requires validation results")
        for result in self.validation_results:
            if result.subject_digest != self.artifact_digest:
                raise ValueError("validation result subject differs from artifact")
            if result.status is not ValidationStatus.PASS:
                raise ValueError("notarization can contain only PASS validation results")
        return self


class RevocationV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["Revocation"] = "Revocation"
    revocation_id: str = Field(min_length=1, max_length=256)
    trust_domain: TrustDomain
    artifact_digests: tuple[Sha256, ...]
    reason_code: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=4000)
    effective_at: datetime
    issued_at: datetime
    issuer: str = Field(min_length=1, max_length=1024)
    signature_bundle_digest: Sha256

    @model_validator(mode="after")
    def non_empty_artifacts(self) -> RevocationV1:
        if not self.artifact_digests:
            raise ValueError("revocation requires at least one artifact digest")
        return self


class VerificationDecisionV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["VerificationDecision"] = "VerificationDecision"
    action: VerificationAction
    status: ValidationStatus
    artifact_digest: Sha256
    trust_domain: TrustDomain
    policy_digest: Sha256
    reason_codes: tuple[str, ...]
    evaluated_at: datetime
    lease_expires_at: datetime | None = None
    evidence: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def allow_requires_pass_and_lease(self) -> VerificationDecisionV1:
        if self.action is VerificationAction.ALLOW:
            if self.status is not ValidationStatus.PASS:
                raise ValueError("allow requires PASS")
            if self.lease_expires_at is None:
                raise ValueError("allow requires a bounded lease")
            if not self.evidence:
                raise ValueError("allow requires immutable evidence")
        return self


class HookSpecV1(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    command: tuple[str, ...]
    timeout_seconds: int = Field(ge=1, le=600)
    network: Literal["none", "allowlist"] = "none"
    allowed_hosts: tuple[str, ...] = ()
    required: bool = True

    @model_validator(mode="after")
    def validate_command_and_network(self) -> HookSpecV1:
        if not self.command:
            raise ValueError("hook command cannot be empty")
        if self.network == "none" and self.allowed_hosts:
            raise ValueError("allowed_hosts requires network=allowlist")
        if self.network == "allowlist" and not self.allowed_hosts:
            raise ValueError("network allowlist cannot be empty")
        return self


class TrustPolicyV1(StrictModel):
    api_version: Literal["skilltrust.dev/v1"] = "skilltrust.dev/v1"
    kind: Literal["TrustPolicy"] = "TrustPolicy"
    policy_id: str = Field(min_length=1, max_length=256)
    version: int = Field(ge=1)
    trust_domain: TrustDomain
    accepted_oidc_issuers: tuple[str, ...] = Field(min_length=1)
    accepted_identities: tuple[str, ...] = Field(min_length=1)
    required_validators: tuple[str, ...] = Field(min_length=1)
    declarative_lease: timedelta = Field(gt=timedelta(0))
    executable_lease: timedelta = Field(gt=timedelta(0))
    max_offline_lease: timedelta = Field(gt=timedelta(0), le=timedelta(days=30))
    runtime_capability_adapters: tuple[str, ...] = ()
    hooks: tuple[HookSpecV1, ...] = ()

    @model_validator(mode="after")
    def validate_leases(self) -> TrustPolicyV1:
        if self.declarative_lease > self.max_offline_lease:
            raise ValueError("declarative lease exceeds maximum")
        if self.executable_lease > self.max_offline_lease:
            raise ValueError("executable lease exceeds maximum")
        if self.trust_domain is TrustDomain.COMMUNITY:
            if self.declarative_lease > timedelta(days=7):
                raise ValueError("community declarative lease cannot exceed 7 days")
            if self.executable_lease > timedelta(hours=24):
                raise ValueError("community executable lease cannot exceed 24 hours")
        return self


def canonical_json_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    """Return stable UTF-8 JSON used for digests and signed subjects."""

    data = (
        value.model_dump(mode="json", exclude_none=True) if isinstance(value, BaseModel) else value
    )
    return json.dumps(
        data,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def utc_now() -> datetime:
    return datetime.now(UTC)
