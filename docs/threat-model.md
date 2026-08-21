# Threat model

## Protected assets

Artifact and policy signing authority, TUF roots/metadata versions, source-to-artifact provenance,
review approvals, OCI digests, revocation state, runtime capability boundaries, audit evidence, and
tenant/repository namespace authorization.

## Adversaries

- malicious contributor, maintainer, dependency, skill content, or validation hook;
- compromised Git account/app/provider, webhook, CI runner/cache, registry, mirror, or online key;
- TLS MITM or attacker holding a valid certificate from an unrelated CA/profile;
- stale/split-view catalog or transparency-log operator;
- local user/process mutating the artifact cache;
- confused deputy that asks the notary to sign an arbitrary digest or cross-tenant namespace.

Kernel/root compromise on a consumer host, compromise of an offline signing threshold, and collusion
of the configured approval threshold are residual risks. They require operational controls outside
this repository.

## Security boundaries

1. Git input and every file inside a skill are untrusted data.
2. Contributor/fork validation receives no signing identity, publish token, production secret, host
   container socket, or unrestricted network.
3. A protected builder fetches the exact immutable repository ID and merged commit, then creates the
   canonical archive itself.
4. Required hooks run only through a sandbox adapter that proves filesystem, secret, and network
   isolation. Missing proof is `UNKNOWN` and denies notarization.
5. A notary signs only a control-plane-created subject whose artifact, manifest, source, approvals,
   policy, and validation evidence all match.
6. Installation and each activation re-check signature identity, TUF freshness, revocation,
   dependency closure, bounded lease, digest, and runtime enforcement capability.

## Confused-deputy defenses

- Repository IDs and commit SHAs are immutable provider values, not contributor names/branches.
- Approval records bind repository ID, head SHA, manifest digest, and artifact digest; a new head is
  a new revision.
- Public WebPKI and private transport roots are not artifact roots. `serverAuth`, `clientAuth`,
  `codeSigning`, and Sigstore OIDC identities are separate policy domains.
- Provider adapters use fixed API bases and typed IDs; they are not arbitrary URL fetchers.
- Sigstore/ORAS commands use argv without a shell and pass exact digest/bundle/identity arguments.
- TUF bootstrap root is supplied from a read-only path outside the writable metadata cache.
- Revocation identifiers and outbox dedupe keys reject conflicting replays.

## Incident response

Stop notary/registry-push identities, preserve database/outbox/log/evidence state, issue signed
artifact or signer revocations, publish fresh TUF targets/snapshot/timestamp metadata, shorten or
invalidate runtime leases, rotate the affected role without reusing TLS keys, and add a regression
test before re-enabling publication.

