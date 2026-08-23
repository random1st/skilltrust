# SkillTrust

**Keep the skills your organisation publishes the ones your people actually run — and put
them back when they change.**

An [Agent Skill](https://agentskills.io/specification) is a folder whose `SKILL.md` an agent
reads and follows, with your credentials. In a company that means prose nobody reviews,
spreading by `git clone` and copy-paste, executing with production access.

Claude Code already gives an organisation a catalog — a plugin marketplace — commit pinning,
and managed settings that decide which marketplaces a machine may use. What it does not give
is a signature over that catalog, a way to withdraw a version already installed, or any check
that the installed copy is still what was fetched: `~/.claude/plugins/cache` is an ordinary
directory an agent can write to, and nothing looks at it again.

SkillTrust is those three things. Sign the marketplace you already publish, verify what each
machine installed from it, put back anything that changed, and revoke one plugin by digest.

Everything outside a signed marketplace is left alone. Not scanned, not restored, not counted.

## For the organisation

```bash
skillctl init --as ops@acme                  # once: the key this marketplace signs with
skillctl marketplace sign ./acme-marketplace
git commit -am "sign the marketplace" && git push
```

```
marketplace acme
sequence    3
signed      12 of 17 plugins

  09ab4c1d95ed  deploy-runbook   1.4.0
  ...

  not signed — 5 plugins hosted elsewhere (git-subdir); this publisher does
  not control those bytes and cannot vouch for them
```

What a signature does not cover is printed, not buried. The official marketplace lists 169
plugins of which 49 are local: a publisher who believes they signed 169 has been misled by
their own tool.

Revoking is one plugin, by digest, so it follows the bytes through a rename or a copy:

```bash
skillctl catalog revoke sha256:… --reason "hardcoded prod credentials"
skillctl marketplace sign ./acme-marketplace
```

## For the machine

```bash
skillctl subscribe git@github.com:acme/marketplace.git --key acme.pub
skillctl sync
```

The publisher's key is pinned from a file you already trust and is never learned from the
marketplace itself — a catalog that could introduce its own signing key could replace itself.

When a signed plugin is edited, it is put back and you are told:

```
skillctl: your organisation's plugins were reconciled

  restored      deploy-runbook   (acme)
                this copy had been changed here and was put back
                what was there: ~/.skilltrust/quarantine/deploy-runbook-20260823T081913Z

These plugins are managed centrally; local changes to them do not survive.
```

Restoring is not a directory swap. Claude Code installs npm dependencies into the cached copy
after fetching, and `.in_use` is a directory of session locks — one file per live session
holding the plugin. The signed tree is laid down fresh and those entries are carried across
whole, so a restore does not break a plugin's dependencies or drop a running session's lock.

## What is deliberate

**Only signed plugins.** The marketplace decides the set, under a signature; a machine never
decides for itself. Claude Code namespaces plugin skills as `plugin:skill`, so a skill with
no prefix is personal or project-local and is passed over without a word. Both directions of
getting this wrong end the product — silence about a signed plugin hides the compromise this
exists to catch, and noise about someone's personal skill gets the tool uninstalled by
lunchtime.

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
| `subscribe` | machine | Follow a marketplace, pinning the publisher's key. |
| `sync` | machine | Fetch, verify, and put back anything that changed. |
| `hook` | machine | Run or install the two reconciler hooks. |
| `init` | publisher | Create the signing key. |
| `marketplace sign` | publisher | Sign the plugins a Claude Code marketplace owns. |
| `marketplace verify` | either | Check installed plugins against a signature. |
| `catalog publish` | publisher | Sign an index of skills in a plain repository. |
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

Paths excluded from a plugin's identity, each for a stated reason: `ATTESTATION.dsse.json`
and `catalog.dsse.json` at the root, because a signature cannot be part of what it signs;
`.in_use` and `node_modules`, because Claude Code owns them. A plugin carrying installed
dependencies is reported as *partially* covered rather than verified — that code is real and
nobody signed it.

A publisher's checkout is not what a consumer receives, so the digest covers git-tracked
files only. The first real marketplace this was pointed at carried 280 MB of build artifacts
that git ignores and no clone has.

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

Working: marketplace signing with honest coverage reporting, verification of the Claude Code
plugin cache, restore with quarantine, revocation by digest, subscription with a pinned key,
both hooks, a CI gate, `lint`, `digest`.

Not built: shipping SkillTrust as a Claude Code plugin, so installing it is `/plugin install`
rather than wiring hooks by hand; `managed-settings.json` guidance, which is the only place
this becomes enforcement rather than detection; a fleet view of which machines are on which
sequence; multiple signatures per marketplace.

## Licence

Proprietary; see [LICENSE.txt](LICENSE.txt).
