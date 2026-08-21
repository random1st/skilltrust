"""Generate committed JSON Schemas from the executable domain contracts."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from pydantic import BaseModel

from skilltrust.attestations import SlsaProvenanceV1
from skilltrust.models import (
    ContributionRequestV1,
    NotarizationV1,
    RevocationV1,
    SkillManifestV1,
    SkillSourceV1,
    TrustPolicyV1,
    ValidationResultV1,
    VerificationDecisionV1,
)
from skilltrust.verification import (
    CatalogVerificationV1,
    SignatureVerificationV1,
    VerificationInputV1,
)

SCHEMAS: dict[str, type[BaseModel]] = {
    "catalog-verification.v1.json": CatalogVerificationV1,
    "contribution-request.v1.json": ContributionRequestV1,
    "notarization.v1.json": NotarizationV1,
    "revocation.v1.json": RevocationV1,
    "slsa-provenance.v1.json": SlsaProvenanceV1,
    "skill-manifest.v1.json": SkillManifestV1,
    "skill-source.v1.json": SkillSourceV1,
    "signature-verification.v1.json": SignatureVerificationV1,
    "trust-policy.v1.json": TrustPolicyV1,
    "validation-result.v1.json": ValidationResultV1,
    "verification-decision.v1.json": VerificationDecisionV1,
    "verification-input.v1.json": VerificationInputV1,
}


def write_schemas(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for filename, model in SCHEMAS.items():
        payload = (
            json.dumps(
                model.model_json_schema(),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        fd, temporary_name = tempfile.mkstemp(prefix=f".{filename}.", dir=destination)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(destination / filename)
        finally:
            temporary.unlink(missing_ok=True)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m skilltrust.schemas DESTINATION")
    write_schemas(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
