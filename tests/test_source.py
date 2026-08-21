from pathlib import Path

import pytest

from skilltrust.models import FileRecord, SourceRef
from skilltrust.source import SourceDeclarationError, load_source_declaration, materialize_manifest

DIGEST = "sha256:" + "a" * 64


def test_materialize_injects_observed_source_and_files(tmp_path: Path) -> None:
    declaration_path = tmp_path / "skilltrust.yaml"
    declaration_path.write_text(
        """\
api_version: skilltrust.dev/v1
kind: SkillSource
name: example-skill
version: 1.0.0
payload_tier: declarative
description: Example skill
"""
    )
    declaration = load_source_declaration(declaration_path)
    source = SourceRef(
        provider="azure-devops",
        repository_id="project-guid/repository-guid",
        clone_url="https://dev.azure.com/acme/project/_git/skills",
        commit_sha="b" * 40,
    )
    manifest = materialize_manifest(
        declaration,
        source=source,
        files=(FileRecord(path="SKILL.md", digest=DIGEST, size=10),),
    )
    assert manifest.source == source
    assert manifest.files[0].path == "SKILL.md"


def test_source_cannot_self_assert_unknown_fields(tmp_path: Path) -> None:
    declaration_path = tmp_path / "skilltrust.yaml"
    declaration_path.write_text(
        """\
api_version: skilltrust.dev/v1
kind: SkillSource
name: example-skill
version: 1.0.0
payload_tier: declarative
description: Example skill
source:
  repository_id: attacker-controlled
"""
    )
    with pytest.raises(SourceDeclarationError, match="invalid source declaration"):
        load_source_declaration(declaration_path)


def test_skill_markdown_is_required(tmp_path: Path) -> None:
    declaration_path = tmp_path / "skilltrust.yaml"
    declaration_path.write_text(
        """\
api_version: skilltrust.dev/v1
kind: SkillSource
name: example-skill
version: 1.0.0
payload_tier: declarative
description: Example skill
"""
    )
    declaration = load_source_declaration(declaration_path)
    source = SourceRef(
        provider="generic-git",
        repository_id="sha256:" + "f" * 64,
        clone_url="https://example.invalid/skills.git",
        commit_sha="b" * 40,
    )
    with pytest.raises(SourceDeclarationError, match=r"must contain SKILL\.md"):
        materialize_manifest(declaration, source=source, files=())
