"""JSON-first Typer application for local SkillTrust operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from skilltrust.models import SkillManifestV1, SourceRef
from skilltrust.service import ServiceError, SkillTrustService
from skilltrust.storage import SkillTrustStorage

app = typer.Typer(add_completion=False, no_args_is_help=True)


def _service() -> SkillTrustService:
    storage = SkillTrustStorage("sqlite+pysqlite:///:memory:")
    storage.create_schema()
    return SkillTrustService(storage=storage)


def _emit_json(payload: object) -> None:
    typer.echo(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _emit_error(error: ServiceError) -> None:
    typer.echo(
        json.dumps(
            {
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                }
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        err=True,
    )
    raise typer.Exit(code=error.exit_code)


def _dispose(service: SkillTrustService) -> None:
    service._storage.dispose()


def _structured_source_ref(
    *,
    source_provider: str,
    repository_id: str,
    clone_url: str,
    commit_sha: str,
    ref: str | None,
    contribution_id: str | None,
) -> SourceRef:
    try:
        return SourceRef(
            provider=source_provider,
            repository_id=repository_id,
            clone_url=clone_url,
            commit_sha=commit_sha,
            ref=ref,
            contribution_id=contribution_id,
        )
    except ValueError as error:
        raise ServiceError(
            "source_ref_invalid",
            f"authenticated source reference is invalid: {error}",
            exit_code=2,
        ) from error


@app.command("pack")
def pack_command(
    source_dir: Path,
    source_provider: Annotated[str, typer.Option(..., "--source-provider")],
    repository_id: Annotated[str, typer.Option(..., "--repository-id")],
    clone_url: Annotated[str, typer.Option(..., "--clone-url")],
    commit_sha: Annotated[str, typer.Option(..., "--commit-sha")],
    ref: Annotated[str | None, typer.Option("--ref")] = None,
    contribution_id: Annotated[str | None, typer.Option("--contribution-id")] = None,
    declaration_name: Annotated[str, typer.Option("--declaration-name")] = "skilltrust.yaml",
    manifest_out: Annotated[Path | None, typer.Option("--manifest-out")] = None,
    archive_out: Annotated[Path | None, typer.Option("--archive-out")] = None,
) -> None:
    """Build a canonical archive plus authenticated manifest from a source tree."""

    service = _service()
    try:
        source = _structured_source_ref(
            source_provider=source_provider,
            repository_id=repository_id,
            clone_url=clone_url,
            commit_sha=commit_sha,
            ref=ref,
            contribution_id=contribution_id,
        )
        packed = service.pack_skill(
            source_dir=source_dir,
            source=source,
            declaration_name=declaration_name,
        )
        if manifest_out is not None:
            service.atomic_write_bytes(
                manifest_out,
                canonical_manifest_bytes(packed.manifest),
            )
        if archive_out is not None:
            service.atomic_write_bytes(archive_out, packed.archive.payload)
        _emit_json(packed.summary.model_dump(mode="json"))
    except ServiceError as error:
        _emit_error(error)
    finally:
        _dispose(service)


@app.command("inspect-archive")
def inspect_archive_command(archive_path: Path) -> None:
    """Validate and inspect an existing canonical archive."""

    service = _service()
    try:
        inspection = service.inspect_archive(archive_path)
        _emit_json(inspection.model_dump(mode="json"))
    except ServiceError as error:
        _emit_error(error)
    finally:
        _dispose(service)


@app.command("cas-ingest")
def cas_ingest_command(
    cas_root: Path,
    archive_path: Path,
    expected_digest: Annotated[str | None, typer.Option("--expected-digest")] = None,
) -> None:
    """Publish a canonical archive into the local CAS."""

    service = _service()
    try:
        result = service.ingest_archive(
            cas_root=cas_root,
            archive_path=archive_path,
            expected_digest=expected_digest,
        )
        _emit_json(result.model_dump(mode="json"))
    except ServiceError as error:
        _emit_error(error)
    finally:
        _dispose(service)


@app.command("cas-activate")
def cas_activate_command(cas_root: Path, digest: str) -> None:
    """Verify and expose an already published CAS object."""

    service = _service()
    try:
        result = service.activate_artifact(cas_root=cas_root, digest=digest)
        _emit_json(result.model_dump(mode="json"))
    except ServiceError as error:
        _emit_error(error)
    finally:
        _dispose(service)


@app.command("generate-schemas")
def generate_schemas_command(destination: Path) -> None:
    """Write committed JSON schemas atomically."""

    service = _service()
    try:
        result = service.generate_schemas(destination)
        _emit_json(result.model_dump(mode="json"))
    except ServiceError as error:
        _emit_error(error)
    finally:
        _dispose(service)


def canonical_manifest_bytes(manifest: SkillManifestV1) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"


if __name__ == "__main__":
    app()
