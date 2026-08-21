# ADR-0001: Separate transport, artifact, catalog, and runtime trust

Status: accepted

## Decision

SkillTrust uses four independent trust layers. No layer substitutes for another.

1. **Transport identity.** Community endpoints use WebPKI/Let's Encrypt; Enterprise endpoints use
   a private ACME CA and mTLS. Certificate path, hostname/SPIFFE identity, EKU, validity, and
   revocation policy are checked. A valid TLS session proves only the peer/channel.
2. **Artifact identity.** Community artifacts use public Sigstore/Fulcio/Rekor. Enterprise artifacts
   use a separate private code-signing intermediate and transparency log. The signed subject is the
   canonical bundle digest plus in-toto provenance—not a Git branch or mutable tag.
3. **Catalog freshness.** Community and Enterprise have separate TUF roots. TUF protects target
   mapping, rollback/freeze resistance, root rotation, and signed revocation state.
4. **Runtime authorization.** A verifier evaluates artifact signature, source commit, validation
   evidence, policy, dependency closure, revocation, lease freshness, payload tier, and runtime
   capability support. `UNKNOWN` is deny. Executable skills cannot run without an enforcement
   adapter.

GitHub and Azure DevOps are source/review systems. OCI is the immutable artifact plane. Git approval
is bound to an exact repository ID and head SHA; an update invalidates approval. A trusted builder
rebuilds from the merged SHA so contributors never supply the final trusted artifact.

## Trust domains

- `community`: public Sigstore and public TUF root; declarative offline lease <= 7 days, executable
  lease <= 24 hours.
- `enterprise`: private signing/log/TUF root; signed policy may choose shorter leases and cannot
  exceed 30 days.

Cross-domain signatures, roots, catalogs, and revocations are never interchangeable.

## Skill tiers

- `declarative`: instructions/resources only; no process execution.
- `executable`: contains an entrypoint; requires sandboxing, declared capabilities, stricter review,
  and a runtime adapter that can actually enforce those capabilities.

## Consequences

The system has more explicit configuration and key-management work, but a compromised web
certificate, Git account, registry tag, or online metadata role cannot alone authorize code. Offline
root and signing-key procedures remain deployment responsibilities and are not emulated locally.

