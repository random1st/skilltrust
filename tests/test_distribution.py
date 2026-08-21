from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tuf.api import exceptions as tuf_exceptions

from skilltrust.distribution import OrasCliAdapter, TufTargetVerifier
from skilltrust.models import ValidationStatus
from skilltrust.providers import CommandResult

DIGEST = "sha256:" + "a" * 64


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
class FakeTargetInfo:
    hashes: dict[str, str]


class FakeUpdater:
    def __init__(
        self,
        metadata_dir: str,
        metadata_base_url: str,
        target_dir: str | None = None,
        target_base_url: str | None = None,
        config: object | None = None,
        *,
        bootstrap: bytes | None,
    ) -> None:
        assert bootstrap is not None
        self.metadata_dir = metadata_dir
        self.metadata_base_url = metadata_base_url
        self.target_dir = target_dir
        self.target_base_url = target_base_url
        self.config = config

    def get_targetinfo(self, target_path: str) -> FakeTargetInfo | None:
        assert target_path == "skills/acme.tgz"
        return FakeTargetInfo({"sha256": "a" * 64})


class ExpiredUpdater(FakeUpdater):
    def get_targetinfo(self, target_path: str) -> FakeTargetInfo | None:
        raise tuf_exceptions.ExpiredMetadataError("timestamp expired")


def test_oras_cli_adapter_passes_for_digest_pinned_reference(tmp_path: Path) -> None:
    runner = QueueRunner(
        [
            CommandResult(("oras",), 0, '{"digest":"sha256:' + "a" * 64 + '"}', ""),
            CommandResult(("oras",), 0, "", ""),
        ]
    )
    output_dir = tmp_path / "bundle"

    result = OrasCliAdapter(runner=runner).pull_by_digest(
        reference=f"registry.example.com/acme/skill@{DIGEST}",
        output_dir=output_dir,
    )

    assert result.status is ValidationStatus.PASS
    assert runner.calls[0][0:4] == ("oras", "manifest", "fetch", "--descriptor")
    assert runner.calls[1][0:2] == ("oras", "pull")


def test_oras_cli_adapter_rejects_mutable_tags() -> None:
    result = OrasCliAdapter().pull_by_digest(
        reference="registry.example.com/acme/skill:latest",
        output_dir=Path("/tmp/ignored"),
    )

    assert result.status is ValidationStatus.FAIL
    assert result.code == "mutable_reference_forbidden"


def test_tuf_target_verifier_passes_on_matching_catalog_digest(tmp_path: Path) -> None:
    bootstrap_root = tmp_path / "bootstrap.root.json"
    bootstrap_root.write_text("{}")
    cache_dir = tmp_path / "cache"

    result = TufTargetVerifier(
        metadata_base_url="https://metadata.example.com",
        targets_base_url="https://targets.example.com",
        bootstrap_root=bootstrap_root,
        cache_dir=cache_dir,
        updater_factory=FakeUpdater,
    ).verify_target(target_path="skills/acme.tgz", expected_digest=DIGEST)

    assert result.status is ValidationStatus.PASS


def test_tuf_target_verifier_fails_closed_on_expired_metadata(tmp_path: Path) -> None:
    bootstrap_root = tmp_path / "bootstrap.root.json"
    bootstrap_root.write_text("{}")
    cache_dir = tmp_path / "cache"

    result = TufTargetVerifier(
        metadata_base_url="https://metadata.example.com",
        targets_base_url="https://targets.example.com",
        bootstrap_root=bootstrap_root,
        cache_dir=cache_dir,
        updater_factory=ExpiredUpdater,
    ).verify_target(target_path="skills/acme.tgz", expected_digest=DIGEST)

    assert result.status is ValidationStatus.FAIL
    assert result.code == "tuf_metadata_rejected"
