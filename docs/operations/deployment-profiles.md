# Deployment profiles

The files in `profiles/` are non-production examples. Copying them does not establish trust.

## Community

- Public HTTPS endpoints: ACME/WebPKI, normally Let's Encrypt, `serverAuth` only.
- Artifact identity: public Sigstore keyless signing with exact OIDC issuer and workflow identity.
- Transparency: public Rekor/Sigstore bundle.
- Catalog: public TUF root shipped read-only with every client.
- Offline leases: declarative <= 7 days; executable <= 24 hours.

## Enterprise

- Service transport/workload identity: private ACME and mTLS.
- Artifact identity: separate private code-signing intermediate or private Sigstore deployment.
- Transparency: private append-only log with independent witness where required.
- Catalog: tenant-specific private TUF root.
- Policy-defined offline leases, never more than 30 days.

## Required production services

Run API and worker as separate identities. Use PostgreSQL for state/outbox, an OCI registry with
immutable-digest retention, object storage for evidence, and a TUF metadata origin. Root/signing
keys live in offline threshold custody or an approved KMS/HSM. Containers mount the bootstrap root
read-only and do not receive Git contributor credentials. Fork validation workers receive no
signing identity, registry push token, production secrets, or unrestricted egress.

TLS termination, private CA, KMS/HSM, registry, PostgreSQL, and TUF hosting are intentionally not
auto-provisioned: provider choices and destructive infrastructure operations require an explicit
deployment decision.

