"""Deterministic archive packaging and guarded extraction for SkillTrust.

.. warning::
   This module is **retired as a digest source**. The canonical archive format has
   exactly one implementation, ``skillctl`` (Go), and this one is kept only so the
   existing CAS tests keep describing the behaviour they were written against.

   The two implementations do not agree, and the disagreement is invisible: both
   produce a valid tar that extracts to an identical tree, yet the digests differ.
   Python's :mod:`tarfile` pads the payload to ``RECORDSIZE`` (20 blocks, 10240
   bytes) where Go emits only the two zero end-of-archive blocks, and Python writes
   eight NUL bytes into ``devmajor``/``devminor`` for regular files where Go writes
   octal zero, moving the header checksum. A notary signing one digest while a client
   computes the other fails as ``artifact_digest_mismatch`` in production with nothing
   in either codebase looking wrong.

   Set ``SKILLTRUST_ALLOW_LEGACY_ARCHIVE=1`` to run it anyway. Nothing that crosses
   the boundary to a client may do so.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from skilltrust.models import FileRecord, sha256_digest


@dataclass(frozen=True)
class ArchiveLimits:
    """Hard limits for untrusted archive packaging and extraction."""

    max_files: int = 1_024
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_archive_bytes: int = 96 * 1024 * 1024


DEFAULT_ARCHIVE_LIMITS = ArchiveLimits()

#: Opt-in for the retired canonicalization. Only the tests that pin its historical
#: behaviour are allowed to set it.
LEGACY_ARCHIVE_ENV = "SKILLTRUST_ALLOW_LEGACY_ARCHIVE"


def _assert_legacy_archive_allowed() -> None:
    if os.environ.get(LEGACY_ARCHIVE_ENV) == "1":
        return
    raise ArchiveError(
        "the canonical archive format is implemented only by skillctl (Go); this "
        "Python implementation produces a different digest for the same tree and must "
        "not be used to produce anything a client will verify. Use "
        "`skillctl digest <dir>`, or set "
        f"{LEGACY_ARCHIVE_ENV}=1 to run the retired implementation deliberately."
    )


@dataclass(frozen=True)
class BuiltArchive:
    """Canonical archive payload plus immutable file metadata."""

    payload: bytes
    digest: str
    files: tuple[FileRecord, ...]


class ArchiveError(RuntimeError):
    """Base class for deterministic archive failures."""


class ArchiveSourceError(ArchiveError):
    """Raised when the local source tree is unsafe or unreadable."""


class ArchivePathError(ArchiveError):
    """Raised when an archive member path is not canonical POSIX."""


class ArchiveCollisionError(ArchiveError):
    """Raised when paths collide after normalization or by ancestry."""


class ArchiveEntryTypeError(ArchiveError):
    """Raised when an archive contains a disallowed entry type."""


class ArchiveLimitError(ArchiveError):
    """Raised when a configured archive size/count limit is exceeded."""


class ArchiveFormatError(ArchiveError):
    """Raised when a tar payload is malformed or truncated."""


@dataclass(frozen=True)
class _CollectedFile:
    path: str
    content: bytes
    executable: bool

    @property
    def record(self) -> FileRecord:
        return FileRecord(
            path=self.path,
            digest=sha256_digest(self.content),
            size=len(self.content),
            executable=self.executable,
        )


class _PathRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, str] = {}
        self._casefold: dict[str, str] = {}

    def register_dir(self, path: str) -> None:
        canonical = _canonical_member_path(path)
        self._register(canonical, kind="dir", allow_existing_dir=True)

    def register_file(self, path: str) -> None:
        canonical = _canonical_member_path(path)
        for parent in _parent_paths(canonical):
            self._register(parent, kind="dir", allow_existing_dir=True)
        self._register(canonical, kind="file", allow_existing_dir=False)

    def _register(self, path: str, *, kind: str, allow_existing_dir: bool) -> None:
        casefold_key = path.casefold()
        existing_casefold = self._casefold.get(casefold_key)
        if existing_casefold is not None and existing_casefold != path:
            raise ArchiveCollisionError(
                "archive path "
                f"'{path}' collides with '{existing_casefold}' after NFC/casefold normalization"
            )

        existing_kind = self._entries.get(path)
        if existing_kind is not None:
            if kind == "dir" and allow_existing_dir and existing_kind == "dir":
                return
            raise ArchiveCollisionError(f"duplicate archive path '{path}' is not allowed")

        for parent in _parent_paths(path):
            if self._entries.get(parent) == "file":
                raise ArchiveCollisionError(
                    f"archive path '{path}' descends from regular file '{parent}'"
                )

        if kind == "file":
            prefix = f"{path}/"
            for existing_path in self._entries:
                if existing_path.startswith(prefix):
                    raise ArchiveCollisionError(
                        f"regular file '{path}' conflicts with descendant '{existing_path}'"
                    )

        self._entries[path] = kind
        self._casefold[casefold_key] = path


def build_archive(
    source_dir: Path, *, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS
) -> BuiltArchive:
    """Create a deterministic tar archive from a local directory tree."""

    _assert_legacy_archive_allowed()

    if not source_dir.is_dir():
        raise ArchiveSourceError(
            f"source directory '{source_dir}' does not exist or is not a directory"
        )

    collected = _collect_source_files(source_dir, limits=limits)
    payload = _encode_tar(collected, limits=limits)
    return BuiltArchive(
        payload=payload,
        digest=sha256_digest(payload),
        files=tuple(file.record for file in collected),
    )


def extract_archive(
    payload: bytes, destination: Path, *, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS
) -> tuple[FileRecord, ...]:
    """Validate and extract a canonical archive into a caller-owned directory."""

    _assert_legacy_archive_allowed()

    if len(payload) > limits.max_archive_bytes:
        raise ArchiveLimitError(
            "archive payload is "
            f"{len(payload)} bytes, above the {limits.max_archive_bytes}-byte limit"
        )

    if destination.exists() and not destination.is_dir():
        raise ArchiveSourceError(
            f"extraction destination '{destination}' exists and is not a directory"
        )
    destination.mkdir(parents=True, exist_ok=True)

    registry = _PathRegistry()
    total_bytes = 0
    file_count = 0
    records: list[FileRecord] = []

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive:
                if not member.isreg():
                    member_type = member.type.decode("ascii", "ignore")
                    raise ArchiveEntryTypeError(
                        f"archive member '{member.name}' uses unsupported type '{member_type}'"
                    )

                path = _canonical_member_path(member.name)
                registry.register_file(path)

                file_count += 1
                if file_count > limits.max_files:
                    raise ArchiveLimitError(
                        "archive contains "
                        f"{file_count} files, above the {limits.max_files}-file limit"
                    )
                if member.size > limits.max_file_bytes:
                    raise ArchiveLimitError(
                        f"archive member '{path}' is {member.size} bytes, above the "
                        f"{limits.max_file_bytes}-byte per-file limit"
                    )

                total_bytes += member.size
                if total_bytes > limits.max_total_bytes:
                    raise ArchiveLimitError(
                        f"archive expands to {total_bytes} bytes, above the "
                        f"{limits.max_total_bytes}-byte total limit"
                    )

                fileobj = archive.extractfile(member)
                if fileobj is None:
                    raise ArchiveFormatError(f"archive member '{path}' could not be read")
                data = fileobj.read()
                if len(data) != member.size:
                    raise ArchiveFormatError(
                        f"archive member '{path}' declared {member.size} bytes "
                        f"but yielded {len(data)} bytes"
                    )

                executable = bool(member.mode & 0o111)
                mode = 0o755 if executable else 0o644
                target = _resolve_destination(destination, path)
                target.parent.mkdir(parents=True, exist_ok=True)
                _write_new_file(target, data, mode=mode)

                records.append(
                    FileRecord(
                        path=path,
                        digest=sha256_digest(data),
                        size=len(data),
                        executable=executable,
                    )
                )
    except ArchiveError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise ArchiveFormatError(f"archive payload is not a readable canonical tar: {exc}") from exc

    records.sort(key=lambda record: record.path)
    return tuple(records)


def _collect_source_files(source_dir: Path, *, limits: ArchiveLimits) -> tuple[_CollectedFile, ...]:
    registry = _PathRegistry()
    collected: list[_CollectedFile] = []
    total_bytes = 0

    def visit(directory: Path) -> None:
        nonlocal total_bytes
        entries = sorted(
            directory.iterdir(),
            key=lambda candidate: (
                unicodedata.normalize("NFC", candidate.name).casefold(),
                unicodedata.normalize("NFC", candidate.name),
            ),
        )
        for entry in entries:
            raw_stat = entry.lstat()
            relative = entry.relative_to(source_dir).as_posix()
            if stat.S_ISLNK(raw_stat.st_mode):
                raise ArchiveEntryTypeError(
                    f"source entry '{relative}' is a symlink; only regular files are allowed"
                )
            if stat.S_ISDIR(raw_stat.st_mode):
                registry.register_dir(relative)
                visit(entry)
                continue
            if not stat.S_ISREG(raw_stat.st_mode):
                raise ArchiveEntryTypeError(
                    f"source entry '{relative}' is not a regular file; "
                    "sockets, devices, and FIFOs are denied"
                )
            if raw_stat.st_nlink != 1:
                raise ArchiveEntryTypeError(
                    f"source entry '{relative}' has {raw_stat.st_nlink} hard links; "
                    "hard-linked files are denied"
                )

            registry.register_file(relative)

            data = _read_regular_file(entry, expected_stat=raw_stat)
            file_size = len(data)
            if file_size > limits.max_file_bytes:
                raise ArchiveLimitError(
                    f"source file '{relative}' is {file_size} bytes, above the "
                    f"{limits.max_file_bytes}-byte per-file limit"
                )

            total_after = total_bytes + file_size
            if total_after > limits.max_total_bytes:
                raise ArchiveLimitError(
                    f"source tree expands to {total_after} bytes, above the "
                    f"{limits.max_total_bytes}-byte total limit"
                )

            collected.append(
                _CollectedFile(
                    path=_canonical_member_path(relative),
                    content=data,
                    executable=bool(raw_stat.st_mode & 0o111),
                )
            )

            if len(collected) > limits.max_files:
                raise ArchiveLimitError(
                    "source tree contains "
                    f"{len(collected)} files, above the {limits.max_files}-file limit"
                )

            total_bytes = total_after

    visit(source_dir)
    collected.sort(key=lambda entry: entry.path)
    return tuple(collected)


def _encode_tar(collected: tuple[_CollectedFile, ...], *, limits: ArchiveLimits) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for entry in collected:
            tarinfo = tarfile.TarInfo(name=entry.path)
            tarinfo.size = len(entry.content)
            tarinfo.mode = 0o755 if entry.executable else 0o644
            tarinfo.mtime = 0
            tarinfo.uid = 0
            tarinfo.gid = 0
            tarinfo.uname = ""
            tarinfo.gname = ""
            tarinfo.pax_headers = {}
            archive.addfile(tarinfo, io.BytesIO(entry.content))

    payload = buffer.getvalue()
    if len(payload) > limits.max_archive_bytes:
        raise ArchiveLimitError(
            "canonical archive is "
            f"{len(payload)} bytes, above the {limits.max_archive_bytes}-byte limit"
        )
    return payload


def _canonical_member_path(path: str) -> str:
    normalized = unicodedata.normalize("NFC", path)
    if not normalized:
        raise ArchivePathError("archive paths cannot be empty")
    if "\x00" in normalized:
        raise ArchivePathError("archive paths cannot contain NUL bytes")
    if "\\" in normalized:
        raise ArchivePathError(f"archive path '{path}' must use POSIX separators only")

    pure = PurePosixPath(normalized)
    if pure.is_absolute():
        raise ArchivePathError(f"archive path '{path}' must be relative")

    parts = pure.parts
    if not parts:
        raise ArchivePathError("archive paths cannot be empty")
    for part in parts:
        if part in {"", ".", ".."}:
            raise ArchivePathError(
                f"archive path '{path}' must not contain empty, '.' , or '..' segments"
            )

    canonical = "/".join(parts)
    if canonical == "":
        raise ArchivePathError("archive paths cannot resolve to the root")
    return canonical


def _parent_paths(path: str) -> tuple[str, ...]:
    parts = path.split("/")
    return tuple("/".join(parts[:index]) for index in range(1, len(parts)))


def _read_regular_file(path: Path, *, expected_stat: os.stat_result) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArchiveSourceError(f"source file '{path}' could not be opened safely: {exc}") from exc

    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ArchiveEntryTypeError(f"source file '{path}' is not a regular file")
        if not _same_source_revision(expected_stat, opened_stat):
            raise ArchiveSourceError(
                f"source file '{path}' changed before it could be packaged; "
                "retry with a stable tree"
            )
        if opened_stat.st_nlink != 1:
            raise ArchiveEntryTypeError(
                f"source file '{path}' has {opened_stat.st_nlink} hard links; "
                "hard-linked files are denied"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as fileobj:
            data = fileobj.read()
        final_stat = os.fstat(descriptor)
        if len(data) != opened_stat.st_size or not _same_source_revision(opened_stat, final_stat):
            raise ArchiveSourceError(
                f"source file '{path}' changed while it was being packaged; "
                "retry with a stable tree"
            )
        return data
    finally:
        os.close(descriptor)


def _same_source_revision(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _resolve_destination(root: Path, path: str) -> Path:
    current = root
    for part in PurePosixPath(path).parts:
        current /= part
    return current


def _write_new_file(path: Path, data: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as fileobj:
            fileobj.write(data)
            fileobj.flush()
    finally:
        os.close(descriptor)
    path.chmod(mode)
