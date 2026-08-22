# SkillTrust

**Keep the skills your organisation publishes the ones your people actually run — and put
them back when they change.**

An [Agent Skill](https://agentskills.io/specification) is a folder whose `SKILL.md` an agent
reads and follows, with your credentials. In a company that means prose nobody reviews,
spreading by `git clone` and copy-paste, executing with production access.

SkillTrust makes a set of those skills *centrally managed*: published from a signed catalog,
verified offline on every machine, restored when a copy is edited, and revocable one skill at
a time.

Everything a catalog does not claim is left alone. Not scanned, not restored, not counted.

## For the organisation

A catalog is a git repository of skills plus a signed index of what it publishes.

```bash
skillctl init --as ops@acme            # once: the key this catalog signs with
skillctl catalog publish ./acme-skills --name acme
git commit -am "publish catalog" && git push
```

```
catalog     acme
sequence    5
publishes   2 skills
revoked     1
valid until 2026-08-29T08:11:09Z
```

The index names each skill and the exact bytes it is supposed to have. Republishing carries
revocations forward and advances the sequence, so nobody can be walked backwards onto an
older set of claims.

In CI, `skillctl catalog verify --key catalog.pub .` fails a pull request when a skill was
changed without republishing. Without that gate a catalog rots silently: the index keeps
naming bytes nobody ships, while still looking authoritative. An ephemeral runner is also the
one place the check is genuinely enforced, since the author of the change has no privileges
there.

Revoking is one skill, by digest, so it follows the bytes through a rename, a move or a copy:

```bash
skillctl catalog revoke sha256:… --reason "leaks the on-call rota"
skillctl catalog publish ./acme-skills
```

## For the machine

```bash
skillctl subscribe git@github.com:acme/skills.git --key acme.pub
skillctl sync
skillctl hook install --apply          # reconcile at the start of every session
```

The publisher's key is pinned from a file you already trust and is never learned from the
catalog itself — a catalog that could introduce its own signing key could replace itself.

When a managed skill is edited, the next session says so and puts it back:

```
skillctl: your organisation's skills were reconciled

  rolled back deploy-runbook   (acme)
              this copy had been changed here and was put back
              what was there: ~/.skilltrust/quarantine/acme/deploy-runbook-20260822T081147Z

These skills are managed centrally; local changes to them do not survive.
```

The replaced copy is kept. Restoring without it would destroy the evidence in the one case
that is an incident.

A skill edited *after* that hook ran is caught in the moment before it loads: the PreToolUse
hook restores it and lets the call through, so the agent reads the published bytes rather
than the edited ones. A revoked skill, or one whose catalog this machine cannot currently
verify, is refused instead — there are no correct bytes to hand over. Skills no catalog
claims are allowed without a word.

`skillctl status` answers the same question without changing anything.

## What is deliberate

**Only managed skills.** The catalog decides the set, under a signature; a machine never
decides for itself. Both directions of getting this wrong end the product — silence about a
managed skill hides the compromise this exists to catch, and noise about someone's personal
skill gets the tool uninstalled by lunchtime.

**Inside that boundary it restores.** That is a stronger claim than the detection this
project otherwise limits itself to, and it is warranted only there: the organisation owns
those bytes, published them and signed them, so putting them back returns the machine to the
state its owner declared.

**The session hook does not touch the network.** A session must not wait on a fetch to a
server behind a VPN that is not up yet. It reconciles against the catalog already on disk,
which still catches the case that matters most and still enforces every revocation the
machine already knows. Refreshing is `skillctl sync`.

**Silence when nothing changed.** A hook that speaks every session is one people stop
reading, and this one has to be read on the day it matters.

**"Could not check" is never "nothing changed".** An expired or unverifiable catalog is
reported loudly, and exit `3` never shares a code with exit `0`.

**Bytes the index does not name are refused.** The catalog is signed; the repository is not.
Installing whatever is in the checkout because the URL was right is the substitution the
signature exists to prevent.

## What this does not claim

**It is not enforcement on a laptop.** Anything able to edit a skill can edit the hook that
checks it, and the client documents that a hook which times out does not block. Real
enforcement needs a boundary the developer does not own — CI, or OS/MDM-managed
configuration. This tells you what happened and undoes it; it does not prevent it.

**`lint` is not a safety verdict.** It reports indicators for a human. No static check can
certify prose an agent will follow.

## Commands

| Command | Side | What it does |
| --- | --- | --- |
| `subscribe` | machine | Follow a catalog, pinning the publisher's key. |
| `sync` | machine | Fetch, verify, reconcile. Restores and removes. |
| `status` | machine | What is managed here and whether it matches. |
| `hook` | machine | Run or install the two reconciler hooks. |
| `init` | publisher | Create the signing key. |
| `catalog publish` | publisher | Sign the index of what a repository publishes. |
| `catalog revoke` | publisher | Revoke digests in that index. |
| `catalog verify` | publisher | Check the index still names what the repository holds. Use in CI. |
| `catalog show` | either | Verify an index and print it. |
| `lint` | either | Inventory a tree and report risk indicators. |
| `digest` | either | The canonical digest of a skill directory. |
| `attest` | either | Sign and verify a statement about a digest. |

## How identity is computed

A skill's identity is the SHA-256 of a canonical PAX tar of its folder: paths sorted, times
and ownership zeroed, modes normalized, NFC paths, symlinks refused, case-fold collisions
refused. One implementation, in Go — a second one in another language is where
reproducibility dies silently.

One path inside a skill is excluded: `ATTESTATION.dsse.json` at the root, so a signature can
travel inside the folder without being part of what it signs. Only that exact name, only at
the root, only as a regular file; anything else there is refused.

Windows has no executable bit, and the bit is part of the identity on purpose, so a skill
containing executables does not produce the same digest there. That is pinned by a test
rather than a footnote.

## Verifying the tool itself

```bash
cd client && make reproducible    # two independent builds, compared
```

Rebuild a release from its tag and compare digests rather than taking our word for it. A
verifier you cannot rebuild is a verifier you have to trust, which is the thing this exists
to avoid. macOS builds are signed and notarized from the maintainer's machine, not from CI:
putting the Developer ID key into a CI secret would place the key that signs every release
wherever the runner lives.

## Status

Working: catalog publishing and signing, a CI gate that the index still matches the
repository, revocation by digest, subscription with a pinned key, offline verification,
reconciliation with rollback and quarantine, both hooks, `lint`, `digest`.

Not built: any distribution of catalogs other than a git repository the machine can reach; a
managed-fleet view of which machines are on which sequence; multiple signatures per catalog
(author plus reviewer).

## Licence

Proprietary; see [LICENSE.txt](LICENSE.txt).
