from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from skilltrust.archive import (
    ArchiveCollisionError,
    ArchiveEntryTypeError,
    ArchiveLimitError,
    ArchiveLimits,
    ArchivePathError,
    build_archive,
    extract_archive,
)

type ArchiveFixture = tuple[tarfile.TarInfo, bytes]


def _tar_bytes(entries: list[ArchiveFixture]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, payload in entries:
            archive.addfile(member, io.BytesIO(payload))
    return buffer.getvalue()


def _regular_member(path: str, payload: bytes) -> ArchiveFixture:
    member = tarfile.TarInfo(path)
    member.size = len(payload)
    member.mode = 0o644
    return member, payload


def _link_member(path: str, member_type: bytes, target: str) -> ArchiveFixture:
    member = tarfile.TarInfo(path)
    member.type = member_type
    member.linkname = target
    member.mode = 0o777
    return member, b""


def _special_member(path: str, member_type: bytes) -> ArchiveFixture:
    member = tarfile.TarInfo(path)
    member.type = member_type
    member.mode = 0o644
    return member, b""


def test_build_archive_is_deterministic_across_mtime_changes(tmp_path: Path) -> None:
    source_dir = tmp_path / "skill"
    source_dir.mkdir()
    script_path = source_dir / "run.sh"
    script_path.write_text("#!/bin/sh\necho safe\n")
    script_path.chmod(0o755)
    nested_dir = source_dir / "docs"
    nested_dir.mkdir()
    readme_path = nested_dir / "readme.txt"
    readme_path.write_text("hello\n")

    first = build_archive(source_dir)

    os.utime(script_path, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    os.utime(readme_path, ns=(1_800_000_000_000_000_000, 1_800_000_000_000_000_000))
    second = build_archive(source_dir)

    assert second.payload == first.payload
    assert second.digest == first.digest
    assert [record.path for record in second.files] == ["docs/readme.txt", "run.sh"]
    assert second.files[1].executable is True


def test_extract_archive_rejects_traversal_paths(tmp_path: Path) -> None:
    payload = _tar_bytes([_regular_member("../escape.txt", b"nope")])

    with pytest.raises(ArchivePathError, match="must not contain"):
        extract_archive(payload, tmp_path / "out")


@pytest.mark.parametrize(
    ("entry", "label"),
    [
        (_link_member("payload.txt", tarfile.SYMTYPE, "target.txt"), "symlink"),
        (_link_member("payload.txt", tarfile.LNKTYPE, "target.txt"), "hardlink"),
        (_special_member("payload.txt", tarfile.FIFOTYPE), "special"),
    ],
)
def test_extract_archive_rejects_non_regular_entries(
    tmp_path: Path, entry: ArchiveFixture, label: str
) -> None:
    payload = _tar_bytes([entry])

    with pytest.raises(ArchiveEntryTypeError, match="unsupported type"):
        extract_archive(payload, tmp_path / label)


@pytest.mark.parametrize(
    "entries",
    [
        [_regular_member("README.txt", b"a"), _regular_member("readme.txt", b"b")],
        [_regular_member("e\u0301.txt", b"a"), _regular_member("\u00e9.txt", b"b")],
    ],
)
def test_extract_archive_rejects_case_and_unicode_collisions(
    tmp_path: Path, entries: list[ArchiveFixture]
) -> None:
    payload = _tar_bytes(entries)

    with pytest.raises(ArchiveCollisionError, match=r"collides|duplicate"):
        extract_archive(payload, tmp_path / "out")


def test_build_archive_rejects_file_count_limit(tmp_path: Path) -> None:
    source_dir = tmp_path / "skill"
    source_dir.mkdir()
    (source_dir / "one.txt").write_text("1")
    (source_dir / "two.txt").write_text("2")

    with pytest.raises(ArchiveLimitError, match="above the 1-file limit"):
        build_archive(source_dir, limits=ArchiveLimits(max_files=1))


def test_extract_archive_rejects_per_file_size_limit(tmp_path: Path) -> None:
    payload = _tar_bytes([_regular_member("large.bin", b"12345")])

    with pytest.raises(ArchiveLimitError, match="per-file limit"):
        extract_archive(payload, tmp_path / "out", limits=ArchiveLimits(max_file_bytes=4))
