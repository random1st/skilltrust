from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from skilltrust.certificates import X509ProfileValidator
from skilltrust.models import TrustDomain, ValidationStatus


def _build_root(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _build_leaf(
    issuer_key: rsa.RSAPrivateKey,
    issuer_certificate: x509.Certificate,
    *,
    common_name: str,
    dns_name: str | None = None,
    extended_key_usages: tuple[x509.ObjectIdentifier, ...],
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage(list(extended_key_usages)), critical=False)
    )
    if dns_name is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def test_tls_server_profile_passes_for_server_auth_leaf() -> None:
    root_key, root_certificate = _build_root("community tls root")
    leaf = _build_leaf(
        root_key,
        root_certificate,
        common_name="skilltrust.example",
        dns_name="skilltrust.example",
        extended_key_usages=(ExtendedKeyUsageOID.SERVER_AUTH,),
    )

    result = X509ProfileValidator().validate_tls_server_certificate(
        leaf,
        hostname="skilltrust.example",
        trust_domain=TrustDomain.COMMUNITY,
        trust_roots=(root_certificate,),
    )

    assert result.status is ValidationStatus.PASS


def test_code_signing_profile_passes_for_pinned_code_signing_root() -> None:
    root_key, root_certificate = _build_root("enterprise artifact root")
    leaf = _build_leaf(
        root_key,
        root_certificate,
        common_name="artifact signer",
        extended_key_usages=(ExtendedKeyUsageOID.CODE_SIGNING,),
    )

    result = X509ProfileValidator().validate_code_signing_certificate(
        leaf,
        trust_domain=TrustDomain.ENTERPRISE,
        trust_anchor=root_certificate,
        trusted_roots=(root_certificate,),
    )

    assert result.status is ValidationStatus.PASS


def test_code_signing_profile_rejects_wrong_trust_domain() -> None:
    community_key, community_root = _build_root("community artifact root")
    enterprise_key, enterprise_root = _build_root("enterprise artifact root")
    leaf = _build_leaf(
        enterprise_key,
        enterprise_root,
        common_name="artifact signer",
        extended_key_usages=(ExtendedKeyUsageOID.CODE_SIGNING,),
    )

    result = X509ProfileValidator().validate_code_signing_certificate(
        leaf,
        trust_domain=TrustDomain.COMMUNITY,
        trust_anchor=enterprise_root,
        trusted_roots=(community_root,),
    )

    assert community_key
    assert result.status is ValidationStatus.FAIL
    assert result.code == "wrong_trust_domain"


def test_code_signing_profile_rejects_any_extended_key_usage() -> None:
    root_key, root_certificate = _build_root("artifact root")
    leaf = _build_leaf(
        root_key,
        root_certificate,
        common_name="artifact signer",
        extended_key_usages=(
            ExtendedKeyUsageOID.CODE_SIGNING,
            ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        ),
    )

    result = X509ProfileValidator().validate_code_signing_certificate(
        leaf,
        trust_domain=TrustDomain.ENTERPRISE,
        trust_anchor=root_certificate,
        trusted_roots=(root_certificate,),
    )

    assert result.status is ValidationStatus.FAIL
    assert result.code == "any_extended_key_usage_forbidden"
