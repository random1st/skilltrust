# SkillTrust security specification

## Security invariants

- Every decision is bound to an artifact `sha256` digest, policy digest, trust domain, evaluation
  time, evidence set, and bounded lease.
- `FAIL` and `UNKNOWN` deny. Missing provider, timeout, malformed evidence, stale TUF metadata,
  network denial, and unsupported runtime are `UNKNOWN` or `FAIL`, never `PASS`.
- TLS server certificates require `serverAuth`; code-signing certificates require `codeSigning` and
  a configured artifact-signing chain. A Let's Encrypt/WebPKI TLS certificate is never accepted as
  an artifact signature.
- Notarization is an in-toto statement over an immutable artifact and exact source commit, with only
  evidence-backed `PASS` validator results.
- Revocation is checked at verify, install, activation, and run time, including transitive
  dependencies. Cached artifacts remain denied after revocation.
- Untrusted archives cannot escape the extraction root, create links/devices, collide by Unicode or
  case folding, exceed file/count/size limits, or mutate between verification and activation.
- Hooks use argv, never a shell; run with a timeout, isolated temporary directory, empty-by-default
  environment, read-only inputs, no secrets, and denied network unless an external sandbox adapter
  proves an allowlist is enforced.

## Contribution state machine

```text
untrusted PR -> policy review at exact head SHA -> trusted post-merge rebuild
-> validator evidence -> notary signature/transparency entry -> OCI by digest
-> TUF target publication -> verify/install/activate/run -> revoke when required
```

Allowed transitions are monotonic except that any state can become `revoked`. Updating PR head SHA
creates a new contribution revision and invalidates old approvals. Publishing mutable tags is
allowed only as a convenience pointer; verification resolves and pins the digest.

## Operational key separation

Root, targets, snapshot, timestamp, artifact signing, TLS server, and workload mTLS keys are distinct
roles. Community and Enterprise roots are distinct. Root and artifact-signing recovery procedures
must be exercised offline; timestamp/snapshot automation uses short-lived scoped identities.

## Required adversarial gates

Tamper, path traversal, link/device entries, archive bomb, Unicode/case collision, wrong EKU,
Let's Encrypt certificate used for code signing, cross-domain bundle, hook failure/timeout/network
request, PR head update, stale/rollback TUF metadata, revoked cached artifact, invalid certificate
time, transitive dependency revocation, unsupported executable runtime, and root rotation.

