"""Test-wide fixtures."""

from __future__ import annotations

import pytest

from skilltrust.archive import LEGACY_ARCHIVE_ENV


@pytest.fixture(autouse=True)
def _allow_retired_canonicalization(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the suite exercise the retired Python canonicalization.

    Production paths must not: the format has one implementation, in Go, and these
    tests exist to describe what the retired one used to do, not to bless it.
    """

    monkeypatch.setenv(LEGACY_ARCHIVE_ENV, "1")
