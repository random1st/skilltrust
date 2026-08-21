from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skilltrust.cli import app

runner = CliRunner()


def test_pack_command_writes_atomic_outputs(tmp_path: Path) -> None:
    skill_dir = _sample_skill_dir(tmp_path / "skill")
    manifest_out = tmp_path / "out" / "manifest.json"
    archive_out = tmp_path / "out" / "bundle.tar"

    result = runner.invoke(
        app,
        [
            "pack",
            str(skill_dir),
            "--source-provider",
            "github",
            "--repository-id",
            "R_123",
            "--clone-url",
            "https://github.com/acme/skills.git",
            "--commit-sha",
            "b" * 40,
            "--manifest-out",
            str(manifest_out),
            "--archive-out",
            str(archive_out),
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["manifest"]["source"]["repository_id"] == "R_123"
    assert manifest_out.exists()
    assert archive_out.exists()


def test_inspect_archive_reports_structured_error(tmp_path: Path) -> None:
    bad_archive = tmp_path / "bad.tar"
    bad_archive.write_bytes(b"not a tar archive")

    result = runner.invoke(app, ["inspect-archive", str(bad_archive)])

    assert result.exit_code == 1
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "archive_invalid"


def test_generate_schemas_command_emits_json(tmp_path: Path) -> None:
    destination = tmp_path / "schemas"

    result = runner.invoke(app, ["generate-schemas", str(destination)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "skill-source.v1.json" in payload["schema_files"]
    assert (destination / "skill-source.v1.json").exists()


def _sample_skill_dir(path: Path) -> Path:
    path.mkdir()
    (path / "SKILL.md").write_text("# Example\n")
    (path / "skilltrust.yaml").write_text(
        """\
api_version: skilltrust.dev/v1
kind: SkillSource
name: example-skill
version: 1.0.0
payload_tier: declarative
description: Example skill
"""
    )
    return path
