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

SkillTrust ships as a Claude Code plugin, so there is nothing to wire by hand:

```
/plugin marketplace add acme/skilltrust
/plugin install skilltrust@skilltrust
```

The plugin puts `skillctl` on the session's `PATH` and brings its own hooks. Every hook is
guarded by `command -v skillctl`, so a platform without a build degrades to one line at
session start rather than a failing hook on every skill invocation — a security check that
breaks the session is a security check people remove.

Then point it at the marketplace you want verified:

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

## Making it binding

On its own this is detection: anything able to edit a plugin can edit the hook that checks
it, and Claude Code documents that a hook which times out does not block. That changes when
an organisation deploys a policy, because managed settings live in a system directory a
developer cannot write to and nothing they set overrides them.

```bash
skillctl policy --marketplace acme --repo acme/claude-plugins --lockdown
```

It prints; it does not install. A policy a machine can grant itself is not a policy — deploy
it with whatever already places files on your fleet:

| | |
| --- | --- |
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

What each key is there for:

| Key | Why |
| --- | --- |
| `enabledPlugins` | Forces SkillTrust on. A check a developer can switch off is a suggestion. |
| `allowManagedHooksOnly` | Only hooks a managed source declares may run — this is what stops the check being removed by the machine it checks. |
| `strictPluginOnlyCustomization` | Skills, agents, hooks and MCP servers may come only from plugins. Without it a skill in `~/.claude/skills` runs with no signature at all and the rest is decoration. |
| `disableSideloadFlags` | `--plugin-dir` and `--plugin-url` would otherwise load a plugin for one run. |
| `disableCommandPluginSources` | A command source fetches its plugin by running a command, which a marketplace allowlist does not constrain. |
| `extraKnownMarketplaces` | Registers your marketplace so a fresh machine has it without anyone typing a command. |
| `strictKnownMarketplaces` | With `--lockdown`, only yours may be added — including instead of Anthropic's official one. |

Run `/status` in Claude Code to confirm: the "Setting sources" line names the managed source
when a policy is in force.

Policy and signatures answer different questions and neither replaces the other. Policy
decides what may run; signatures decide whether what runs is what you published.

## The notary

Everything above works with a git repository and no server. The notary is the hosted step
on top: a service that countersigns what a publisher signed and serves it to machines.

```
CI signs the marketplace ──PUT──▶ notaryd ──countersigns──▶ machines fetch over HTTPS
        (publisher key)              │                        (skillctl sync)
                                     └──── machines file signed events ──▶ skillctl fleet
```

```bash
skillctl subscribe git@github.com:acme/marketplace.git \
  --catalog https://notary.acme.com/v1/catalogs/acme/plugins \
  --key acme.pub --key notary.pub --threshold 2
```

What it buys, concretely: a revocation reaches machines on the next `sync` rather than on
the publisher's next push; publishing from CI needs no long-lived secret, because a GitHub
Actions job authenticates with the OIDC token GitHub mints for it and the notary checks
which repository it belongs to; and the fleet's signed events collect somewhere an
administrator can read with one command.

What it deliberately does not buy is trust. The notary is a second signer, never the only
one: a machine that pins both keys with `--threshold 2` is safe against either key alone
being stolen, and a compromised notary can publish nothing, because the catalogs it serves
must still carry the publisher's signature — which it does not have. The session hook still
never touches the network; `sync` fetches the countersigned index and keeps it locally, and
a notary outage degrades to the staleness the freshness check already handles. Tokens are
three narrow roles (publish, ingest, admin), so a leak of any one stays the size of its
role.

Run it yourself: `notaryd --config notary.json` — one static binary, state is files in a
directory, the countersigning key provisions itself on first boot.

## Hearing about it

An incident only the developer it happened to can see is not an incident anyone acts on.
Every restore, revocation and unverifiable check produces an event, signed by the machine that
filed it, and sent wherever you already look:

```json
{
  "machine": "laptop-roman",
  "destinations": [
    { "kind": "webhook", "url": "https://hooks.slack.com/services/…" },
    { "kind": "command", "command": ["logger", "-t", "skilltrust"] },
    { "kind": "file", "directory": "/Volumes/security/skilltrust" }
  ]
}
```

That is `~/.skilltrust/reporting.json`, placed by the same configuration management that
places the policy. A webhook receives a `text` line a Slack hook can render and the whole
event beside it for a SIEM that reads every field; `command` is the escape hatch that reaches
any transport you already run without this project growing an integration for each.

Reporting is an output and never an input. If the network is gone, a tampered plugin is still
detected and still put back — only the telling is delayed, and the event waits in a local
spool rather than being lost. A check that needs a server to reach a verdict fails open the
first time the server is unreachable, which is exactly when it matters.

```
$ skillctl fleet /Volumes/security/skilltrust
laptop-roman
  last report      2026-08-23T10:26:22Z
  restored         4
  catalog-unusable 1
    08-23 10:26  s5d was changed on laptop-roman and put back to what s5d publishes

1 machine reporting · 5 events
1 file refused: not signed by a machine in ~/.skilltrust/trusted-keys.json
```

A console starts as a reader over signed files you already have: no service to run, no
database, no port to defend. Reports that no trusted machine signed are refused rather than
counted — an aggregate built from unverifiable rows looks like evidence and is not. A hosted
console can be built on this later; what it cannot be built on is a fleet that never reported.

Which machines count is one command per machine, not a JSON file to hand-edit:

```bash
skillctl trust laptop-roman.pub        # pin; the file name becomes the label
skillctl trust                         # list what is pinned
skillctl trust --remove laptop-roman   # decommission deliberately
```

Repointing an existing label to a different key is refused — that is how an attacker's key
would inherit a name everyone already trusts. Remove first, then pin.

## What this does not claim

**Without a managed policy it is detection, not enforcement.** On an unmanaged laptop the
hook is a convention, and a convention can be edited by whoever can edit the thing it guards.

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
| `policy` | publisher | Print the managed settings that make the check binding. |
| `trust` | admin | Pin a key, list the pinned set, or remove a label. |
| `fleet` | admin | Summarise the signed events your machines filed. |
| `catalog verify` | publisher | Check the index still names what the repository holds. Used by the action. |
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
to avoid. macOS builds are signed and notarized from the maintainer's machine, not from CI: putting the
Developer ID key into a CI secret would place the key that signs every release wherever the
runner lives. Publishing is therefore one path — `make release` locally. Pushing a tag no
longer starts a second, unsigned release racing the first under the same version.

## Status

Working: marketplace signing with honest coverage reporting, verification of the Claude Code
plugin cache, restore with quarantine, revocation by digest, subscription with pinned keys
and a signature threshold, both hooks, a CI gate, the notary (countersigning, catalog
serving, event collection, OIDC publishing), `fleet` over a directory or the notary,
`lint`, `digest`.

Not built: a web interface for the console; billing or any multi-tenant management beyond
the notary's per-organisation configuration.

## Layout

```
action.yml     the GitHub Action that runs the gate and talks to the notary
client/        skillctl — the CLI. One static binary, two dependencies.
server/        notaryd — the notary. Same story: one binary, files for state.
internal/      the packages both sides are built from: digest, DSSE, catalog, reporting
plugin/        the Claude Code plugin: hooks, and the binary shim that finds skillctl
docs/          the threat model, and running the gate in other CIs
```

The Go module lives at the root so that the notary service and the client verify with the
same code. Two implementations of a digest agree until the day it matters; this layout
makes a second one impossible to add by accident.

There was once a Python control plane here, and documents describing four trust layers, a
private ACME CA and a transparency log. None of it was built. It was removed rather than left
to imply the product does things it does not — an architecture document nobody implemented is
read as a specification, and this one would have been read as a promise.

## Licence

Proprietary; see [LICENSE.txt](LICENSE.txt).
