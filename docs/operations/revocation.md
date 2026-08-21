# Revocation runbook

Certificate revocation and skill revocation solve different problems. CRL/OCSP can revoke a signing
credential; a `RevocationV1` revokes exact artifact digests (and therefore every dependent artifact
through dependency closure).

1. Freeze new notarization/publication for the affected namespace or signer.
2. Create a typed revocation with unique ID, domain, exact digest list, reason, effective time, issuer,
   and signature-bundle digest.
3. Sign it with the domain's revocation/metadata authority and append it to durable storage. A reused
   ID with different content is rejected.
4. Publish the new revocation target and monotonically newer TUF targets, snapshot, and timestamp.
5. Confirm independent clients observe the new metadata before restoring normal publication.
6. Re-notarize a fixed version under a new digest; never remove or rewrite the old revocation.

Clients check revocation during verify, install, activation, and invocation. A cached prior `ALLOW`
becomes deny immediately after a matching revocation and becomes `UNKNOWN`/deny when its freshness
lease expires. Metadata rollback, freeze, missing root, or unavailable refresh past the lease never
soft-fails.

