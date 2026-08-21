"""Fail-closed signing adapters for Sigstore and private PKI verification."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography import x509

from skilltrust.certificates import X509ProfileValidator
from skilltrust.models import Sha256, TrustDomain, ValidationStatus
from skilltrust.providers.base import (
    ArtifactVerificationResult,
    CommandRunner,
    SubprocessCommandRunner,
    digest_file,
)


@dataclass(frozen=True)
class PrivateSignatureProof:
    verifier: str
    status: ValidationStatus
    code: str
    message: str
    signing_certificate: x509.Certificate | None = None
    trust_anchor: x509.Certificate | None = None
    evidence: tuple[Sha256, ...] = ()


@runtime_checkable
class PrivateSignatureVerifier(Protocol):
    def verify(self, *, artifact: Path, signature: Path) -> PrivateSignatureProof: ...


class SigstoreCliVerifier:
    """Use the official Sigstore CLI as an external verifier without shell expansion."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        executable: str = "sigstore",
        timeout_seconds: float = 30.0,
    ) -> None:
        self._runner = runner or SubprocessCommandRunner()
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def verify_identity(
        self,
        *,
        artifact: Path,
        bundle: Path,
        identity: str,
        issuer: str,
        offline: bool = True,
        staging: bool = False,
        trust_config: Path | None = None,
    ) -> ArtifactVerificationResult:
        artifact_digest = self._safe_digest(artifact, code="artifact_unreadable")
        if isinstance(artifact_digest, ArtifactVerificationResult):
            return artifact_digest

        bundle_digest = self._safe_digest(
            bundle,
            code="bundle_unreadable",
            artifact_digest=artifact_digest,
        )
        if isinstance(bundle_digest, ArtifactVerificationResult):
            return bundle_digest

        if staging and trust_config is not None:
            return ArtifactVerificationResult(
                provider="sigstore",
                status=ValidationStatus.FAIL,
                code="sigstore_conflicting_instance_config",
                message="Sigstore staging and trust-config options are mutually exclusive",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest, bundle_digest),
            )

        argv = [self._executable]
        if staging:
            argv.append("--staging")
        if trust_config is not None:
            argv.extend(["--trust-config", str(trust_config)])
        argv.extend(
            [
                "verify",
                "identity",
                "--bundle",
                str(bundle),
                "--cert-identity",
                identity,
                "--cert-oidc-issuer",
                issuer,
            ]
        )
        if offline:
            argv.append("--offline")
        argv.append(str(artifact))

        try:
            result = self._runner.run(tuple(argv), timeout_seconds=self._timeout_seconds)
        except FileNotFoundError:
            return ArtifactVerificationResult(
                provider="sigstore",
                status=ValidationStatus.UNKNOWN,
                code="sigstore_unavailable",
                message="Sigstore CLI is not installed or not on PATH",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest, bundle_digest),
            )
        except (OSError, TimeoutError) as exc:
            return ArtifactVerificationResult(
                provider="sigstore",
                status=ValidationStatus.UNKNOWN,
                code="sigstore_execution_error",
                message=f"Sigstore CLI could not verify the artifact: {exc}",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest, bundle_digest),
            )

        if result.returncode != 0:
            return ArtifactVerificationResult(
                provider="sigstore",
                status=ValidationStatus.UNKNOWN,
                code="sigstore_nonzero_exit",
                message=(
                    "Sigstore CLI did not produce a trusted verification result for the exact "
                    "artifact and bundle"
                ),
                artifact_digest=artifact_digest,
                evidence=(artifact_digest, bundle_digest),
                details={"stderr": result.stderr.strip() or result.stdout.strip()},
            )

        return ArtifactVerificationResult(
            provider="sigstore",
            status=ValidationStatus.PASS,
            code="sigstore_identity_verified",
            message=(
                "Sigstore CLI verified the exact artifact against the pinned identity and issuer"
            ),
            artifact_digest=artifact_digest,
            evidence=(artifact_digest, bundle_digest),
        )

    def _safe_digest(
        self,
        path: Path,
        *,
        code: str,
        artifact_digest: Sha256 | None = None,
    ) -> Sha256 | ArtifactVerificationResult:
        try:
            return digest_file(path)
        except OSError as exc:
            return ArtifactVerificationResult(
                provider="sigstore",
                status=ValidationStatus.UNKNOWN,
                code=code,
                message=f"required verification input could not be read: {exc}",
                artifact_digest=artifact_digest or ("sha256:" + "0" * 64),
            )


class PrivateSigningVerifier:
    """Enforce pinned artifact roots and code-signing profiles around external signature checks."""

    def __init__(
        self,
        *,
        verifier: PrivateSignatureVerifier,
        pinned_artifact_roots: Sequence[Path],
        trusted_signing_roots: Mapping[TrustDomain, Sequence[x509.Certificate]],
        validator: X509ProfileValidator | None = None,
    ) -> None:
        self._verifier = verifier
        self._pinned_artifact_roots = tuple(
            root.resolve(strict=False) for root in pinned_artifact_roots
        )
        self._trusted_signing_roots = {
            domain: tuple(roots)
            for domain, roots in trusted_signing_roots.items()
        }
        self._validator = validator or X509ProfileValidator()

    def verify(
        self,
        *,
        artifact: Path,
        signature: Path,
        trust_domain: TrustDomain,
    ) -> ArtifactVerificationResult:
        artifact_path = artifact.resolve(strict=False)
        artifact_digest = self._artifact_digest(artifact_path)

        if not self._pinned_artifact_roots:
            return ArtifactVerificationResult(
                provider="private-signing",
                status=ValidationStatus.FAIL,
                code="artifact_roots_unconfigured",
                message="Private signing verification requires pinned artifact roots",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )
        if not self._is_under_pinned_root(artifact_path):
            return ArtifactVerificationResult(
                provider="private-signing",
                status=ValidationStatus.FAIL,
                code="artifact_root_unpinned",
                message="Artifact path is outside the pinned artifact roots",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )

        trusted_roots = self._trusted_signing_roots.get(trust_domain, ())
        if not trusted_roots:
            return ArtifactVerificationResult(
                provider="private-signing",
                status=ValidationStatus.FAIL,
                code="signing_roots_unconfigured",
                message="Pinned artifact signing roots are required for the requested trust domain",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )

        try:
            proof = self._verifier.verify(artifact=artifact_path, signature=signature)
        except (OSError, TimeoutError, ValueError) as exc:
            return ArtifactVerificationResult(
                provider="private-signing",
                status=ValidationStatus.UNKNOWN,
                code="private_signature_verifier_unavailable",
                message=f"private signature verification could not complete: {exc}",
                artifact_digest=artifact_digest,
                evidence=(artifact_digest,),
            )

        if proof.status is not ValidationStatus.PASS:
            return ArtifactVerificationResult(
                provider="private-signing",
                status=proof.status,
                code=proof.code,
                message=proof.message,
                artifact_digest=artifact_digest,
                evidence=self._merge_evidence(artifact_digest, proof.evidence),
            )
        if proof.signing_certificate is None or proof.trust_anchor is None:
            return ArtifactVerificationResult(
                provider="private-signing",
                status=ValidationStatus.UNKNOWN,
                code="private_signature_material_missing",
                message=(
                    "External signature verifier did not return the signing certificate and "
                    "trust anchor"
                ),
                artifact_digest=artifact_digest,
                evidence=self._merge_evidence(artifact_digest, proof.evidence),
            )

        certificate_result = self._validator.validate_code_signing_certificate(
            proof.signing_certificate,
            trust_domain=trust_domain,
            trust_anchor=proof.trust_anchor,
            trusted_roots=trusted_roots,
        )
        if certificate_result.status is not ValidationStatus.PASS:
            return ArtifactVerificationResult(
                provider="private-signing",
                status=certificate_result.status,
                code=certificate_result.code,
                message=certificate_result.message,
                artifact_digest=artifact_digest,
                evidence=self._merge_evidence(
                    artifact_digest,
                    (*proof.evidence, certificate_result.fingerprint),
                ),
            )

        return ArtifactVerificationResult(
            provider="private-signing",
            status=ValidationStatus.PASS,
            code="private_signature_verified",
            message="Private signature and pinned code-signing profile match the exact artifact",
            artifact_digest=artifact_digest,
            evidence=self._merge_evidence(
                artifact_digest,
                (*proof.evidence, certificate_result.fingerprint),
            ),
        )

    def _artifact_digest(self, artifact: Path) -> Sha256:
        try:
            return digest_file(artifact)
        except OSError:
            return "sha256:" + "0" * 64

    def _is_under_pinned_root(self, artifact: Path) -> bool:
        return any(artifact.is_relative_to(root) for root in self._pinned_artifact_roots)

    def _merge_evidence(
        self,
        artifact_digest: Sha256,
        evidence: Sequence[Sha256],
    ) -> tuple[Sha256, ...]:
        ordered: list[Sha256] = [artifact_digest]
        for item in evidence:
            if item not in ordered:
                ordered.append(item)
        return tuple(ordered)
