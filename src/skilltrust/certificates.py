"""X.509 profile validation for transport and artifact trust domains."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from skilltrust.models import TrustDomain, ValidationStatus, utc_now
from skilltrust.providers.base import (
    CertificateProfile,
    CertificateValidationResult,
)

ANY_EXTENDED_KEY_USAGE = ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE


class X509ProfileValidator:
    """Keep TLS transport identities separate from artifact-signing identities."""

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or utc_now

    def validate_tls_server_certificate(
        self,
        leaf: x509.Certificate,
        *,
        hostname: str,
        trust_domain: TrustDomain,
        trust_roots: Sequence[x509.Certificate],
        intermediates: Sequence[x509.Certificate] = (),
    ) -> CertificateValidationResult:
        failure = self._base_leaf_checks(
            leaf,
            profile=CertificateProfile.TLS_SERVER,
            trust_domain=trust_domain,
        )
        if failure is not None:
            return failure
        if not trust_roots:
            return self._fail(
                leaf,
                profile=CertificateProfile.TLS_SERVER,
                trust_domain=trust_domain,
                code="tls_root_unpinned",
                message="TLS validation requires at least one pinned trust root",
            )

        eku = self._get_extended_key_usage(leaf)
        if eku is None or ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            return self._fail(
                leaf,
                profile=CertificateProfile.TLS_SERVER,
                trust_domain=trust_domain,
                code="tls_server_auth_required",
                message="TLS certificates must contain the serverAuth EKU",
            )
        if ANY_EXTENDED_KEY_USAGE in eku:
            return self._fail(
                leaf,
                profile=CertificateProfile.TLS_SERVER,
                trust_domain=trust_domain,
                code="any_extended_key_usage_forbidden",
                message="Certificates with anyExtendedKeyUsage are rejected",
            )
        if ExtendedKeyUsageOID.CODE_SIGNING in eku:
            return self._fail(
                leaf,
                profile=CertificateProfile.TLS_SERVER,
                trust_domain=trust_domain,
                code="mixed_eku_forbidden",
                message="TLS certificates cannot double as code-signing certificates",
            )

        try:
            verifier = (
                PolicyBuilder()
                .store(Store(list(trust_roots)))
                .time(self._now())
                .build_server_verifier(x509.DNSName(hostname))
            )
            verifier.verify(leaf, list(intermediates))
        except VerificationError as exc:
            return self._fail(
                leaf,
                profile=CertificateProfile.TLS_SERVER,
                trust_domain=trust_domain,
                code="tls_chain_invalid",
                message=f"TLS certificate chain validation failed: {exc}",
            )

        return self._pass(
            leaf,
            profile=CertificateProfile.TLS_SERVER,
            trust_domain=trust_domain,
            code="tls_server_profile_valid",
            message="TLS certificate satisfies serverAuth profile and pinned trust roots",
        )

    def validate_code_signing_certificate(
        self,
        leaf: x509.Certificate,
        *,
        trust_domain: TrustDomain,
        trust_anchor: x509.Certificate,
        trusted_roots: Sequence[x509.Certificate],
    ) -> CertificateValidationResult:
        failure = self._base_leaf_checks(
            leaf,
            profile=CertificateProfile.ARTIFACT_SIGNER,
            trust_domain=trust_domain,
        )
        if failure is not None:
            return failure
        if not trusted_roots:
            return self._fail(
                leaf,
                profile=CertificateProfile.ARTIFACT_SIGNER,
                trust_domain=trust_domain,
                code="artifact_root_unpinned",
                message="Artifact signing validation requires pinned artifact trust roots",
            )

        eku = self._get_extended_key_usage(leaf)
        if eku is None or ExtendedKeyUsageOID.CODE_SIGNING not in eku:
            return self._fail(
                leaf,
                profile=CertificateProfile.ARTIFACT_SIGNER,
                trust_domain=trust_domain,
                code="code_signing_eku_required",
                message="Artifact signing certificates must contain the codeSigning EKU",
            )
        if ANY_EXTENDED_KEY_USAGE in eku:
            return self._fail(
                leaf,
                profile=CertificateProfile.ARTIFACT_SIGNER,
                trust_domain=trust_domain,
                code="any_extended_key_usage_forbidden",
                message="Certificates with anyExtendedKeyUsage are rejected",
            )
        if ExtendedKeyUsageOID.SERVER_AUTH in eku:
            return self._fail(
                leaf,
                profile=CertificateProfile.ARTIFACT_SIGNER,
                trust_domain=trust_domain,
                code="mixed_eku_forbidden",
                message="Artifact signing certificates cannot double as TLS server certificates",
            )

        anchor_constraints = trust_anchor.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not anchor_constraints.ca:
            return self._fail(
                leaf,
                profile=CertificateProfile.ARTIFACT_SIGNER,
                trust_domain=trust_domain,
                code="trust_anchor_not_ca",
                message="Pinned artifact trust anchor must be a certificate authority",
            )

        pinned_fingerprints = {self._fingerprint(root) for root in trusted_roots}
        anchor_fingerprint = self._fingerprint(trust_anchor)
        if anchor_fingerprint not in pinned_fingerprints:
            return self._fail(
                leaf,
                profile=CertificateProfile.ARTIFACT_SIGNER,
                trust_domain=trust_domain,
                code="wrong_trust_domain",
                message=(
                    "Artifact signing trust anchor is not pinned for the requested trust "
                    "domain"
                ),
            )

        return self._pass(
            leaf,
            profile=CertificateProfile.ARTIFACT_SIGNER,
            trust_domain=trust_domain,
            code="code_signing_profile_valid",
            message="Artifact signing certificate matches the pinned code-signing profile",
        )

    def _base_leaf_checks(
        self,
        leaf: x509.Certificate,
        *,
        profile: CertificateProfile,
        trust_domain: TrustDomain,
    ) -> CertificateValidationResult | None:
        constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        if constraints.ca:
            return self._fail(
                leaf,
                profile=profile,
                trust_domain=trust_domain,
                code="leaf_must_not_be_ca",
                message="End-entity certificates must not be marked as certificate authorities",
            )

        now = self._now()
        if now < leaf.not_valid_before_utc:
            return self._fail(
                leaf,
                profile=profile,
                trust_domain=trust_domain,
                code="certificate_not_yet_valid",
                message="Certificate is not yet valid at the verification time",
            )
        if now > leaf.not_valid_after_utc:
            return self._fail(
                leaf,
                profile=profile,
                trust_domain=trust_domain,
                code="certificate_expired",
                message="Certificate expired before the verification time",
            )

        return None

    def _get_extended_key_usage(
        self,
        certificate: x509.Certificate,
    ) -> x509.ExtendedKeyUsage | None:
        try:
            return certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            return None

    def _pass(
        self,
        certificate: x509.Certificate,
        *,
        profile: CertificateProfile,
        trust_domain: TrustDomain,
        code: str,
        message: str,
    ) -> CertificateValidationResult:
        return CertificateValidationResult(
            provider="x509-profile",
            status=ValidationStatus.PASS,
            code=code,
            message=message,
            profile=profile,
            trust_domain=trust_domain,
            fingerprint=self._fingerprint(certificate),
            subject=certificate.subject.rfc4514_string(),
            issuer=certificate.issuer.rfc4514_string(),
        )

    def _fail(
        self,
        certificate: x509.Certificate,
        *,
        profile: CertificateProfile,
        trust_domain: TrustDomain,
        code: str,
        message: str,
    ) -> CertificateValidationResult:
        return CertificateValidationResult(
            provider="x509-profile",
            status=ValidationStatus.FAIL,
            code=code,
            message=message,
            profile=profile,
            trust_domain=trust_domain,
            fingerprint=self._fingerprint(certificate),
            subject=certificate.subject.rfc4514_string(),
            issuer=certificate.issuer.rfc4514_string(),
        )

    def _fingerprint(self, certificate: x509.Certificate) -> str:
        return f"sha256:{sha256(certificate.public_bytes(Encoding.DER)).hexdigest()}"
