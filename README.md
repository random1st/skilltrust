# SkillTrust

SkillTrust is a provider-neutral control plane for reviewing, packaging, notarizing,
publishing, installing, and revoking agent skills. Git is the contribution and review plane;
immutable OCI artifacts are the distribution plane; Sigstore/private PKI prove publisher and
builder identity; TUF is the freshness and revocation catalog.

The reference implementation is deliberately fail-closed. A TLS certificate authenticates a
transport endpoint only. It never makes a skill trusted. `PASS`, `FAIL`, and `UNKNOWN` are distinct,
and `UNKNOWN` never authorizes installation or execution.

## Quick start

```bash
make setup
make check
uv run skillctl --help
uv run skilltrustd --help
```

See [the architecture decision](docs/architecture/0001-trust-model.md) and
[the security specification](docs/security-specification.md) before deploying.

## Status

This repository provides a production-oriented vertical slice and local reference backend. Public
Sigstore, private PKI, OCI, TUF, GitHub, and Azure DevOps are explicit provider adapters. External
services and production keys are not bundled; an unavailable or unconfigured provider is reported
as `UNKNOWN`/deny instead of being simulated.

