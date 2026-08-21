# Git contribution adapters

Git is the review plane, not the install-time trust root. All providers normalize to:

- provider and immutable repository ID;
- exact head/merge commit SHA;
- contribution/PR ID;
- review subjects and decision bound to that SHA;
- provider status evidence.

## GitHub

Use a GitHub App with minimum repository permissions. Verify webhook HMAC before parsing events,
reject replayed delivery IDs, resolve the repository node/database ID, and query the PR head SHA
again immediately before recording approval. Protect the release workflow and branch with rulesets,
required reviews/status checks, no force pushes, and no unreviewed bypass. Fork workflows never get
the notary OIDC identity.

## Azure DevOps

Use Microsoft Entra workload identity with project/repository scope. Resolve project/repository GUIDs,
PR ID and `lastMergeSourceCommit.commitId`; require branch build/reviewer/status policies. Where signed
commit enforcement is required, publish a custom verifier status because it must not be assumed from
branch policy alone.

## Generic Git

Generic Git is read-only intake. Its repository ID is a canonical hash of the normalized remote URL;
it cannot record trusted reviews or publish provider status. Promotion therefore requires a separate
authenticated approval authority.

Provider API failures, head changes, missing reviews, rate limits, and malformed payloads are
structured `UNKNOWN`/deny results.

