"""Convert an untrusted source declaration into a builder-authenticated manifest."""

from __future__ import annotations

from pathlib import Path

import yaml

from skilltrust.models import FileRecord, SkillManifestV1, SkillSourceV1, SourceRef


class SourceDeclarationError(ValueError):
    """The contributor-authored declaration is missing or invalid."""


def load_source_declaration(path: Path) -> SkillSourceV1:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SourceDeclarationError(f"cannot read source declaration {path}: {exc}") from exc
    try:
        value = yaml.safe_load(payload)
    except yaml.YAMLError as exc:
        raise SourceDeclarationError(f"invalid YAML in source declaration {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SourceDeclarationError("source declaration must be a YAML object")
    try:
        return SkillSourceV1.model_validate(value)
    except ValueError as exc:
        raise SourceDeclarationError(f"invalid source declaration {path}: {exc}") from exc


def materialize_manifest(
    declaration: SkillSourceV1,
    *,
    source: SourceRef,
    files: tuple[FileRecord, ...],
) -> SkillManifestV1:
    """Inject SCM-authenticated source and builder-observed files into the release manifest."""

    paths = {record.path for record in files}
    if "SKILL.md" not in paths:
        raise SourceDeclarationError("skill source must contain SKILL.md")
    missing_entrypoints = sorted(set(declaration.entrypoints) - paths)
    if missing_entrypoints:
        raise SourceDeclarationError(
            "declared entrypoints are absent from the packaged files: "
            + ", ".join(missing_entrypoints)
        )
    return SkillManifestV1(
        name=declaration.name,
        version=declaration.version,
        payload_tier=declaration.payload_tier,
        source=source,
        description=declaration.description,
        entrypoints=declaration.entrypoints,
        files=files,
        capabilities=declaration.capabilities,
        dependencies=declaration.dependencies,
        metadata=declaration.metadata,
    )
