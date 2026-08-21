# Security policy

Do not open a public issue containing an exploitable vulnerability, credential, private certificate,
or production artifact. Report privately to the deployment owner and include the affected version,
artifact digest, trust domain, reproduction, and whether signing/metadata keys may be compromised.

Never attach private keys, OIDC tokens, registry credentials, TUF root-signing material, database
dumps, or raw hook output containing confidential data. Rotate exposed credentials before sharing a
sanitized report.

See `docs/threat-model.md` and `docs/operations/revocation.md` for containment and revocation.

