from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from skilltrust.models import TrustDomain, ValidationStatus
from skilltrust.providers import CommandResult
from skilltrust.signing import (
    PrivateSignatureProof,
    PrivateSigningVerifier,
    SigstoreCliVerifier,
)


class QueueRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path | None = None,
        input_bytes: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        assert cwd is None
        assert input_bytes is None
        assert timeout_seconds is not None
        self.calls.append(argv)
        return self.results.pop(0)


@dataclass
class StaticPrivateVerifier:
    proof: PrivateSignatureProof

    def verify(self, *, artifact: Path, signature: Path) -> PrivateSignatureProof:
        assert artifact.exists()
        assert signature.exists()
        return self.proof


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
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _build_code_signing_leaf(
    issuer_key: rsa.RSAPrivateKey,
    issuer_certificate: x509.Certificate,
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "artifact signer")])
    now = datetime.now(UTC)
    return (
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def test_sigstore_cli_verifier_passes_and_uses_bundle_identity_and_issuer(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    bundle = tmp_path / "artifact.bundle.json"
    artifact.write_bytes(b"artifact")
    bundle.write_text("{}")
    runner = QueueRunner([CommandResult(("sigstore",), 0, "", "")])

    result = SigstoreCliVerifier(runner=runner).verify_identity(
        artifact=artifact,
        bundle=bundle,
        identity="https://github.com/acme/skills/.github/workflows/release.yml@refs/heads/main",
        issuer="https://token.actions.githubusercontent.com",
    )

    assert result.status is ValidationStatus.PASS
    assert runner.calls[0][0:3] == ("sigstore", "verify", "identity")
    assert "--bundle" in runner.calls[0]


def test_sigstore_cli_verifier_returns_unknown_on_nonzero_exit(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    bundle = tmp_path / "artifact.bundle.json"
    artifact.write_bytes(b"artifact")
    bundle.write_text("{}")
    runner = QueueRunner([CommandResult(("sigstore",), 1, "", "verification failed")])

    result = SigstoreCliVerifier(runner=runner).verify_identity(
        artifact=artifact,
        bundle=bundle,
        identity="identity@example.com",
        issuer="https://issuer.example.com",
    )

    assert result.status is ValidationStatus.UNKNOWN
    assert result.code == "sigstore_nonzero_exit"


def test_private_signing_verifier_passes_with_pinned_root_and_code_signing_certificate(
    tmp_path: Path,
) -> None:
    root_key, root_certificate = _build_root("enterprise artifact root")
    leaf = _build_code_signing_leaf(root_key, root_certificate)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    artifact = artifact_root / "skill.tar"
    artifact.write_bytes(b"payload")
    signature = tmp_path / "skill.tar.sig"
    signature.write_bytes(b"sig")
    verifier = StaticPrivateVerifier(
        PrivateSignatureProof(
            verifier="pkcs7",
            status=ValidationStatus.PASS,
            code="signature_verified",
            message="signature ok",
            signing_certificate=leaf,
            trust_anchor=root_certificate,
            evidence=("sha256:" + "b" * 64,),
        )
    )

    result = PrivateSigningVerifier(
        verifier=verifier,
        pinned_artifact_roots=(artifact_root,),
        trusted_signing_roots={TrustDomain.ENTERPRISE: (root_certificate,)},
    ).verify(
        artifact=artifact,
        signature=signature,
        trust_domain=TrustDomain.ENTERPRISE,
    )

    assert result.status is ValidationStatus.PASS
    assert result.code == "private_signature_verified"


def test_private_signing_verifier_fails_for_artifact_outside_pinned_root(tmp_path: Path) -> None:
    root_key, root_certificate = _build_root("enterprise artifact root")
    leaf = _build_code_signing_leaf(root_key, root_certificate)
    pinned_root = tmp_path / "pinned"
    pinned_root.mkdir()
    artifact = tmp_path / "outside.tar"
    artifact.write_bytes(b"payload")
    signature = tmp_path / "outside.tar.sig"
    signature.write_bytes(b"sig")
    verifier = StaticPrivateVerifier(
        PrivateSignatureProof(
            verifier="pkcs7",
            status=ValidationStatus.PASS,
            code="signature_verified",
            message="signature ok",
            signing_certificate=leaf,
            trust_anchor=root_certificate,
        )
    )

    result = PrivateSigningVerifier(
        verifier=verifier,
        pinned_artifact_roots=(pinned_root,),
        trusted_signing_roots={TrustDomain.ENTERPRISE: (root_certificate,)},
    ).verify(
        artifact=artifact,
        signature=signature,
        trust_domain=TrustDomain.ENTERPRISE,
    )

    assert result.status is ValidationStatus.FAIL
    assert result.code == "artifact_root_unpinned"
