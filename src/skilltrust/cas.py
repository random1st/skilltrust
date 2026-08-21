"""Read-only content-addressable storage for verified SkillTrust bundles."""

from __future__ import annotations

import errno
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from skilltrust.archive import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveError,
    ArchiveLimits,
    build_archive,
    extract_archive,
)
from skilltrust.models import FileRecord, sha256_digest


@dataclass(frozen=True)
class StoredArtifact:
    """Published CAS object backed by a read-only extracted payload tree."""

    digest: str
    path: Path
    files: tuple[FileRecord, ...]


class CasError(RuntimeError):
    """Base class for CAS publish and activation failures."""


class CasDigestError(CasError):
    """Raised when bytes do not match the claimed content digest."""


class CasNotFoundError(CasError):
    """Raised when a requested CAS object is absent."""


class CasTamperError(CasError):
    """Raised when a stored CAS object is no longer immutable or intact."""


class CasPublishError(CasError):
    """Raised when a validated object cannot be published atomically."""


class ContentAddressableStore:
    """Secure local CAS that publishes verified payloads by immutable digest."""

    def __init__(self, root: Path, *, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS) -> None:
        self._root = root
        self._limits = limits
        self._objects_root = root / "objects" / "sha256"
        self._staging_root = root / "staging"
        self._objects_root.mkdir(parents=True, exist_ok=True)
        self._staging_root.mkdir(parents=True, exist_ok=True)

    def ingest_archive(self, payload: bytes, *, expected_digest: str) -> StoredArtifact:
        """Extract, verify, and atomically publish a digest-bound archive."""

        digest_hex = _parse_digest(expected_digest)
        actual_digest = sha256_digest(payload)
        if actual_digest != expected_digest:
            raise CasDigestError(
                f"archive digest mismatch: expected {expected_digest}, received {actual_digest}"
            )

        final_object_dir = self.object_path(expected_digest)
        if final_object_dir.exists():
            return self.activate(expected_digest)

        stage_root = Path(tempfile.mkdtemp(prefix=f"{digest_hex[:12]}-", dir=self._staging_root))
        object_dir = stage_root / "object"
        payload_dir = object_dir / "payload"
        payload_dir.mkdir(parents=True)

        try:
            extract_archive(payload, payload_dir, limits=self._limits)
            _make_tree_read_only(payload_dir)
            rebuilt = build_archive(payload_dir, limits=self._limits)
            if rebuilt.digest != expected_digest:
                raise CasDigestError(
                    "extracted payload digest mismatch: "
                    f"expected {expected_digest}, rebuilt {rebuilt.digest}"
                )

            try:
                object_dir.rename(final_object_dir)
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise CasPublishError(
                        f"CAS object '{expected_digest}' could not be published atomically: {exc}"
                    ) from exc
                return self.activate(expected_digest)

            final_object_dir.chmod(0o555)
            return StoredArtifact(
                digest=expected_digest,
                path=final_object_dir / "payload",
                files=rebuilt.files,
            )
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)

    def activate(self, digest: str) -> StoredArtifact:
        """Verify a stored payload before making it available for use."""

        object_dir = self.object_path(digest)
        payload_dir = object_dir / "payload"
        if not payload_dir.is_dir():
            raise CasNotFoundError(f"CAS object '{digest}' is not present")

        _assert_tree_read_only(payload_dir, digest=digest)
        try:
            rebuilt = build_archive(payload_dir, limits=self._limits)
        except ArchiveError as exc:
            raise CasTamperError(
                f"CAS object '{digest}' failed structural verification: {exc}"
            ) from exc

        if rebuilt.digest != digest:
            raise CasTamperError(
                f"CAS object '{digest}' failed digest verification after rehash; "
                f"rebuilt {rebuilt.digest}"
            )

        return StoredArtifact(digest=digest, path=payload_dir, files=rebuilt.files)

    def object_path(self, digest: str) -> Path:
        """Return the object directory for a validated digest string."""

        digest_hex = _parse_digest(digest)
        return self._objects_root / digest_hex


def _parse_digest(digest: str) -> str:
    prefix, separator, hex_digest = digest.partition(":")
    if prefix != "sha256" or separator != ":" or len(hex_digest) != 64:
        raise CasDigestError(
            f"digest '{digest}' must use the form 'sha256:<64 lowercase hex characters>'"
        )
    if any(character not in "0123456789abcdef" for character in hex_digest):
        raise CasDigestError(
            f"digest '{digest}' must use the form 'sha256:<64 lowercase hex characters>'"
        )
    return hex_digest


def _make_tree_read_only(root: Path) -> None:
    for entry in sorted(root.iterdir(), key=lambda candidate: candidate.name):
        entry_stat = entry.lstat()
        if stat.S_ISDIR(entry_stat.st_mode):
            _make_tree_read_only(entry)
            entry.chmod(0o555)
            continue
        if not stat.S_ISREG(entry_stat.st_mode):
            raise CasPublishError(
                f"staged CAS payload contains unsupported entry '{entry}'"
            )
        mode = 0o555 if entry_stat.st_mode & 0o111 else 0o444
        entry.chmod(mode)
    root.chmod(0o555)


def _assert_tree_read_only(root: Path, *, digest: str) -> None:
    if root.lstat().st_mode & 0o222:
        raise CasTamperError(
            f"CAS object '{digest}' keeps write bits on '{root.name}'; activation is denied"
        )
    for entry in sorted(root.iterdir(), key=lambda candidate: candidate.name):
        entry_stat = entry.lstat()
        if entry_stat.st_mode & 0o222:
            raise CasTamperError(
                f"CAS object '{digest}' is writable at "
                f"'{entry.relative_to(root)}'; activation is denied"
            )
        if stat.S_ISDIR(entry_stat.st_mode):
            _assert_tree_read_only(entry, digest=digest)
            continue
        if not stat.S_ISREG(entry_stat.st_mode):
            raise CasTamperError(
                f"CAS object '{digest}' contains unsupported stored entry '{entry}'"
            )
