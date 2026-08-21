"""Build strict SLSA v1 predicates for Sigstore's DSSE/in-toto attestation path."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from skilltrust.models import NotarizationV1, StrictModel


class ResourceDescriptor(StrictModel):
    uri: str = Field(min_length=1, max_length=2048)
    digest: dict[Literal["sha256", "gitCommit"], str]


class SlsaBuildDefinitionV1(StrictModel):
    build_type: Literal["https://skilltrust.dev/build/v1"] = Field(
        default="https://skilltrust.dev/build/v1",
        serialization_alias="buildType",
    )
    external_parameters: dict[str, Any] = Field(serialization_alias="externalParameters")
    internal_parameters: dict[str, Any] = Field(serialization_alias="internalParameters")
    resolved_dependencies: tuple[ResourceDescriptor, ...] = Field(
        serialization_alias="resolvedDependencies"
    )


class SlsaBuilderV1(StrictModel):
    id: str = Field(min_length=1, max_length=1024)


class SlsaBuildMetadataV1(StrictModel):
    invocation_id: str = Field(
        min_length=1,
        max_length=512,
        serialization_alias="invocationId",
    )
    started_on: datetime = Field(serialization_alias="startedOn")
    finished_on: datetime = Field(serialization_alias="finishedOn")


class SlsaRunDetailsV1(StrictModel):
    builder: SlsaBuilderV1
    metadata: SlsaBuildMetadataV1


class SlsaProvenanceV1(StrictModel):
    """Predicate accepted by `sigstore attest --predicate-type .../provenance/v1`."""

    build_definition: SlsaBuildDefinitionV1 = Field(serialization_alias="buildDefinition")
    run_details: SlsaRunDetailsV1 = Field(serialization_alias="runDetails")


def slsa_predicate_from_notarization(
    notarization: NotarizationV1,
    *,
    policy_digest: str,
    invocation_id: str,
) -> SlsaProvenanceV1:
    """Bind exact source, artifact policy, and validator evidence into SLSA provenance."""

    artifact_sha256 = notarization.artifact_digest.removeprefix("sha256:")
    manifest_sha256 = notarization.manifest_digest.removeprefix("sha256:")
    started_at = min(result.started_at for result in notarization.validation_results)
    finished_at = max(result.completed_at for result in notarization.validation_results)
    validations = [
        {
            "validator": result.validator,
            "version": result.validator_version,
            "code": result.code,
            "evidence": list(result.evidence),
        }
        for result in notarization.validation_results
    ]
    return SlsaProvenanceV1(
        build_definition=SlsaBuildDefinitionV1(
            external_parameters={
                "artifactDigest": artifact_sha256,
                "manifestDigest": manifest_sha256,
                "trustDomain": notarization.trust_domain.value,
                "validations": validations,
            },
            internal_parameters={"policyDigest": policy_digest},
            resolved_dependencies=(
                ResourceDescriptor(
                    uri=notarization.source.clone_url,
                    digest={"gitCommit": notarization.source.commit_sha},
                ),
            ),
        ),
        run_details=SlsaRunDetailsV1(
            builder=SlsaBuilderV1(id=notarization.builder_identity),
            metadata=SlsaBuildMetadataV1(
                invocation_id=invocation_id,
                started_on=started_at,
                finished_on=finished_at,
            ),
        ),
    )
