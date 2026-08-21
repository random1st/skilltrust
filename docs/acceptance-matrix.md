# Acceptance matrix

`make check` is the canonical local gate. External-service rows remain `UNKNOWN` until executed
against configured infrastructure and recorded with subject digest, environment, checker version,
and time.

| Requirement | Enforced by | Automated evidence |
|---|---|---|
| Deterministic bundle and bit-tamper detection | `archive.py`, `cas.py` | `test_archive.py`, `test_cas.py` |
| Traversal/link/device/case/Unicode/limit rejection | `archive.py` | `test_archive.py` |
| Exact repo/head/digest approvals | `policy.py`, `storage.py`, Git adapters | `test_policy.py`, `test_storage.py`, `test_providers.py` |
| Hook failure/timeout/no sandbox/no network proof deny | `hooks.py` | `test_hooks.py` |
| TLS and artifact EKU/domain separation | `certificates.py` | `test_certificates.py` |
| Sigstore exact identity/issuer/bundle verification | `signing.py` | mocked CLI contract tests; live public service is `UNKNOWN` |
| OCI digest-only publication/pull | `distribution.py` | mocked ORAS contract tests; live registry is `UNKNOWN` |
| TUF root/freshness/rollback enforcement | `distribution.py`, `verification.py` | adapter/freshness tests; live root rotation is `UNKNOWN` |
| Direct and transitive revocation | `lifecycle.py`, `verification.py`, `storage.py` | lifecycle/verification/storage tests |
| Executable denied without real runtime adapter | `policy.py`, `verification.py` | policy/verification tests |
| Community 7d/24h and Enterprise <=30d leases | `models.py`, `verification.py` | model/verification tests |
| Stale cached decision denied | `lifecycle.py` | lifecycle tests |
| Community/Enterprise cross-domain denial | `verification.py`, adapters | verification/integration tests |

