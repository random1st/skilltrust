"""Shared contracts and utilities for fail-closed provider adapters."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import Field

from skilltrust.models import GitSha, Sha256, StrictModel, TrustDomain, ValidationStatus


class ReviewVerdict(StrEnum):
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    PENDING = "pending"
    UNKNOWN = "unknown"


class CheckVerdict(StrEnum):
    PASS = "pass"  # noqa: S105 - validation state, not a secret
    FAIL = "fail"
    PENDING = "pending"
    UNKNOWN = "unknown"


class CertificateProfile(StrEnum):
    TLS_SERVER = "tls-server"
    ARTIFACT_SIGNER = "artifact-signer"


class IntegrationResult(StrictModel):
    provider: str = Field(min_length=1, max_length=128)
    status: ValidationStatus
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4000)
    details: dict[str, str] = Field(default_factory=dict)


class ContributionCheckResult(IntegrationResult):
    repository_id: str = Field(min_length=1, max_length=512)
    contribution_id: str = Field(min_length=1, max_length=256)
    head_sha: GitSha
    review_verdict: ReviewVerdict = ReviewVerdict.UNKNOWN
    checks_verdict: CheckVerdict = CheckVerdict.UNKNOWN
    approvers: tuple[str, ...] = ()


class ArtifactVerificationResult(IntegrationResult):
    artifact_digest: Sha256
    evidence: tuple[Sha256, ...] = ()


class CertificateValidationResult(IntegrationResult):
    profile: CertificateProfile
    trust_domain: TrustDomain
    fingerprint: Sha256
    subject: str = Field(min_length=1, max_length=2048)
    issuer: str = Field(min_length=1, max_length=2048)


class GitRevision(StrictModel):
    repository_id: str = Field(min_length=1, max_length=512)
    clone_url: str = Field(min_length=1, max_length=2048)
    ref: str = Field(min_length=1, max_length=512)
    commit_sha: GitSha


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@runtime_checkable
class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input_bytes: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult: ...


class SubprocessCommandRunner:
    """Run subprocesses without a shell so provider inputs stay argv-safe."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input_bytes: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        try:
            completed = subprocess.run(  # noqa: S603
                list(argv),
                # Command arguments are passed as argv, never shell-expanded.
                check=False,
                cwd=cwd,
                input=input_bytes,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"command timed out after {timeout_seconds} seconds") from exc

        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        return CommandResult(tuple(argv), completed.returncode, stdout, stderr)


@runtime_checkable
class JsonHttpClient(Protocol):
    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> object: ...


class HttpxJsonClient:
    """Small JSON-only HTTP client for provider adapters."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        self._timeout_seconds = timeout_seconds

    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> object:
        response = httpx.get(url, headers=dict(headers or {}), timeout=self._timeout_seconds)
        response.raise_for_status()
        return response.json()


def as_mapping(value: object, *, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be a JSON object")
    return value


def as_list(value: object, *, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be a JSON array")
    return value


def digest_file(path: Path) -> Sha256:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"
