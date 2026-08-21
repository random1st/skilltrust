"""Configuration loading with strict schemas and no ambient trust defaults."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from skilltrust.models import TrustPolicyV1


class ConfigurationError(ValueError):
    """Configuration was absent or did not satisfy the signed-policy schema."""


class ServiceSettings(BaseSettings):
    """Process settings; secrets are referenced, never embedded in policy files."""

    model_config = SettingsConfigDict(
        env_prefix="SKILLTRUST_",
        env_file=None,
        extra="forbid",
        frozen=True,
    )

    database_url: str = "sqlite+pysqlite:///./.skilltrust/control-plane.db"
    cas_root: Path = Path(".skilltrust/cas")
    trust_policy_path: Path
    tuf_bootstrap_root: Path
    tuf_metadata_url: str
    tuf_targets_url: str
    runtime_adapter: str | None = None
    request_body_limit: int = Field(default=1_048_576, ge=1024, le=16_777_216)


def load_trust_policy(path: Path) -> TrustPolicyV1:
    """Load a strict policy document.

    Authenticity is intentionally checked by the caller's TUF/signature adapter before this
    parser is invoked. Parsing a YAML file alone never makes it trusted.
    """

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"cannot read trust policy {path}: {exc}") from exc
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in trust policy {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("trust policy must be a YAML object")
    try:
        return TrustPolicyV1.model_validate(value)
    except ValueError as exc:
        raise ConfigurationError(f"invalid trust policy {path}: {exc}") from exc
