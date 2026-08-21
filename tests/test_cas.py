from __future__ import annotations

from pathlib import Path

import pytest

from skilltrust.archive import build_archive
from skilltrust.cas import CasDigestError, CasTamperError, ContentAddressableStore


def test_ingest_archive_is_idempotent_and_publishes_read_only_payload(tmp_path: Path) -> None:
    source_dir = _sample_skill_dir(tmp_path / "skill")
    built = build_archive(source_dir)
    store = ContentAddressableStore(tmp_path / "cas")

    first = store.ingest_archive(built.payload, expected_digest=built.digest)
    second = store.ingest_archive(built.payload, expected_digest=built.digest)

    assert first.path == second.path
    assert first.files == second.files
    assert not (first.path.stat().st_mode & 0o222)
    for file_path in first.path.rglob("*"):
        assert not (file_path.lstat().st_mode & 0o222)


def test_ingest_archive_rejects_bit_tamper_against_expected_digest(tmp_path: Path) -> None:
    source_dir = _sample_skill_dir(tmp_path / "skill")
    built = build_archive(source_dir)
    store = ContentAddressableStore(tmp_path / "cas")

    tampered = bytearray(built.payload)
    tampered[600] ^= 0x01

    with pytest.raises(CasDigestError, match="digest mismatch"):
        store.ingest_archive(bytes(tampered), expected_digest=built.digest)


def test_activate_denies_tampered_stored_artifact(tmp_path: Path) -> None:
    source_dir = _sample_skill_dir(tmp_path / "skill")
    built = build_archive(source_dir)
    store = ContentAddressableStore(tmp_path / "cas")

    stored = store.ingest_archive(built.payload, expected_digest=built.digest)
    payload_file = stored.path / "run.sh"
    payload_file.chmod(0o644)
    payload_file.write_text("#!/bin/sh\necho pwned\n")
    payload_file.chmod(0o444)

    with pytest.raises(CasTamperError, match="digest verification"):
        store.activate(built.digest)


def _sample_skill_dir(path: Path) -> Path:
    path.mkdir()
    run_path = path / "run.sh"
    run_path.write_text("#!/bin/sh\necho safe\n")
    run_path.chmod(0o555)
    (path / "README.txt").write_text("docs\n")
    return path
