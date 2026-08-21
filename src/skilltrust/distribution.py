"""Distribution adapters for OCI registries and TUF catalogs."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, runtime_checkable

from tuf.api import exceptions as tuf_exceptions
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.updater import Updater

from skilltrust.models import Sha256, ValidationStatus
from skilltrust.providers.base import (
    ArtifactVerificationResult,
    CommandRunner,
    SubprocessCommandRunner,
)

OCI_DIGEST_REFERENCE = re.compile(r"^(?P<name>[^@\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")


@runtime_checkable
class TufUpdaterLike(Protocol):
    def get_targetinfo(self, target_path: str) -> object | None: ...


class OrasCliAdapter:
    """Use ORAS only with immutable digest references."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        executable: str = "oras",
        timeout_seconds: float = 30.0,
    ) -> None:
        self._runner = runner or SubprocessCommandRunner()
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def pull_by_digest(self, *, reference: str, output_dir: Path) -> ArtifactVerificationResult:
        parsed = OCI_DIGEST_REFERENCE.fullmatch(reference)
        if parsed is None:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.FAIL,
                code="mutable_reference_forbidden",
                message=(
                    "OCI distribution requires an immutable digest reference, never a mutable "
                    "tag"
                ),
                artifact_digest="sha256:" + "0" * 64,
            )

        artifact_digest = parsed.group("digest")
        descriptor_result = self._fetch_descriptor(reference, artifact_digest)
        if descriptor_result.status is not ValidationStatus.PASS:
            return descriptor_result

        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = self._runner.run(
                (
                    self._executable,
                    "pull",
                    "--output",
                    str(output_dir),
                    reference,
                ),
                timeout_seconds=self._timeout_seconds,
            )
        except FileNotFoundError:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_unavailable",
                message="ORAS CLI is not installed or not on PATH",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )
        except (OSError, TimeoutError) as exc:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_execution_error",
                message=f"ORAS CLI could not pull the immutable artifact: {exc}",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )

        if result.returncode != 0:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_nonzero_exit",
                message="ORAS CLI did not produce a trusted immutable artifact pull result",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
                details={"stderr": result.stderr.strip() or result.stdout.strip()},
            )

        return ArtifactVerificationResult(
            provider="oras",
            status=ValidationStatus.PASS,
            code="oras_digest_pull_verified",
            message="ORAS pulled the immutable artifact addressed by digest",
            artifact_digest=artifact_digest,
            evidence=(artifact_digest,),
        )

    def _fetch_descriptor(
        self,
        reference: str,
        artifact_digest: Sha256,
    ) -> ArtifactVerificationResult:
        try:
            result = self._runner.run(
                (
                    self._executable,
                    "manifest",
                    "fetch",
                    "--descriptor",
                    "--format",
                    "json",
                    reference,
                ),
                timeout_seconds=self._timeout_seconds,
            )
        except FileNotFoundError:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_unavailable",
                message="ORAS CLI is not installed or not on PATH",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )
        except (OSError, TimeoutError) as exc:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_execution_error",
                message=f"ORAS CLI could not inspect the immutable artifact: {exc}",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )

        if result.returncode != 0:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_nonzero_exit",
                message="ORAS CLI did not return a descriptor for the immutable artifact reference",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
                details={"stderr": result.stderr.strip() or result.stdout.strip()},
            )

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_descriptor_malformed",
                message=f"ORAS descriptor output was malformed JSON: {exc}",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )
        if not isinstance(payload, dict):
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.UNKNOWN,
                code="oras_descriptor_malformed",
                message="ORAS descriptor output must be a JSON object",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )

        descriptor_digest = payload.get("digest")
        if descriptor_digest != artifact_digest:
            return ArtifactVerificationResult(
                provider="oras",
                status=ValidationStatus.FAIL,
                code="oras_descriptor_digest_mismatch",
                message="ORAS descriptor digest does not match the immutable reference digest",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
                details={"descriptor_digest": str(descriptor_digest)},
            )

        return ArtifactVerificationResult(
            provider="oras",
            status=ValidationStatus.PASS,
            code="oras_descriptor_verified",
            message="ORAS descriptor matches the immutable reference digest",
            artifact_digest=artifact_digest,
            evidence=(artifact_digest,),
        )


class TufTargetVerifier:
    """Verify TUF target bindings with stable ngclient semantics and fail-closed metadata checks."""

    def __init__(
        self,
        *,
        metadata_base_url: str,
        targets_base_url: str,
        bootstrap_root: Path,
        cache_dir: Path,
        updater_factory: Callable[..., TufUpdaterLike] = Updater,
        config: UpdaterConfig | None = None,
    ) -> None:
        self._metadata_base_url = metadata_base_url
        self._targets_base_url = targets_base_url
        self._bootstrap_root = bootstrap_root
        self._cache_dir = cache_dir
        self._updater_factory = updater_factory
        self._config = config or UpdaterConfig()

    def verify_target(
        self,
        *,
        target_path: str,
        expected_digest: Sha256,
    ) -> ArtifactVerificationResult:
        bootstrap_root = self._bootstrap_root.resolve(strict=False)
        cache_dir = self._cache_dir.resolve(strict=False)
        if bootstrap_root.is_relative_to(cache_dir):
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.FAIL,
                code="mutable_bootstrap_root_forbidden",
                message="TUF bootstrap root must live outside the writable metadata cache",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
            )

        try:
            bootstrap = self._bootstrap_root.read_bytes()
            metadata_dir = self._cache_dir / "metadata"
            target_dir = self._cache_dir / "targets"
            metadata_dir.mkdir(parents=True, exist_ok=True)
            target_dir.mkdir(parents=True, exist_ok=True)
            updater = self._updater_factory(
                str(metadata_dir),
                self._metadata_base_url,
                target_dir=str(target_dir),
                target_base_url=self._targets_base_url,
                config=self._config,
                bootstrap=bootstrap,
            )
            targetinfo = updater.get_targetinfo(target_path)
        except (
            tuf_exceptions.BadVersionNumberError,
            tuf_exceptions.EqualVersionNumberError,
            tuf_exceptions.ExpiredMetadataError,
            tuf_exceptions.LengthOrHashMismatchError,
            tuf_exceptions.RepositoryError,
            tuf_exceptions.UnsignedMetadataError,
        ) as exc:
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.FAIL,
                code="tuf_metadata_rejected",
                message=f"TUF metadata verification failed closed: {exc}",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
            )
        except (tuf_exceptions.DownloadError, OSError, ValueError) as exc:
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.UNKNOWN,
                code="tuf_unavailable",
                message=f"TUF target verification could not complete: {exc}",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
            )

        if targetinfo is None:
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.FAIL,
                code="tuf_target_missing",
                message="Requested target is not published in the trusted TUF metadata",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
            )

        hashes = getattr(targetinfo, "hashes", None)
        if not isinstance(hashes, dict):
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.UNKNOWN,
                code="tuf_targetinfo_malformed",
                message="TUF target metadata did not expose a hash mapping",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
            )

        actual_digest = hashes.get("sha256")
        if not isinstance(actual_digest, str):
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.FAIL,
                code="tuf_sha256_missing",
                message="TUF target metadata is missing the required sha256 digest",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
            )

        canonical_digest = f"sha256:{actual_digest}"
        if canonical_digest != expected_digest:
            return ArtifactVerificationResult(
                provider="tuf",
                status=ValidationStatus.FAIL,
                code="tuf_digest_mismatch",
                message="TUF target digest does not match the pinned immutable artifact digest",
                artifact_digest=expected_digest,
                evidence=(expected_digest,),
                details={"catalog_digest": canonical_digest},
            )

        return ArtifactVerificationResult(
            provider="tuf",
            status=ValidationStatus.PASS,
            code="tuf_target_verified",
            message="TUF target metadata matches the pinned immutable artifact digest",
            artifact_digest=expected_digest,
            evidence=(expected_digest,),
        )
