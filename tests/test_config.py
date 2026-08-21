from pathlib import Path

import pytest

from skilltrust.config import ConfigurationError, load_trust_policy
from skilltrust.models import TrustDomain


def test_load_community_profile() -> None:
    policy = load_trust_policy(Path("profiles/community.example.yaml"))
    assert policy.trust_domain is TrustDomain.COMMUNITY


def test_unknown_policy_field_is_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("api_version: skilltrust.dev/v1\nkind: TrustPolicy\noops: true\n")
    with pytest.raises(ConfigurationError, match="invalid trust policy"):
        load_trust_policy(policy)
