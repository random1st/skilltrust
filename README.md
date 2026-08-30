# SkillTrust

**Keep the skills your organisation publishes the ones your people actually run — and put
them back when they change.**

> **SkillTrust and Axela are two things.** This repository is SkillTrust: the client that
> checks your machines and the notary you can run yourself, Apache-2.0, no key of yours
> anywhere near us. [Axela](https://axela.app) is a hosted notary built on it — somewhere
> to point the client if you would rather not run one. You never need it: everything here
> works against your own server, and the split is
> spelled out under [Status](#status).

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
/plugin marketplace add random1st/skilltrust
/plugin install skilltrust@skilltrust
```

Or install the two commands directly, which is what the hosted console's setup assumes:

```bash
brew install random1st/tap/skillctl        # skillctl and skilltrust-mcp
claude mcp add skilltrust -- skilltrust-mcp
```

The plugin puts `skillctl` on the session's `PATH` and brings its own hooks. What is on PATH
is a shim that picks the binary for the machine; builds ship for macOS and Linux on both
architectures and for Windows on amd64. On anything else the shim prints where to get one and
exits 0, so a session starts with a line rather than a failing hook on every skill invocation
— a security check that breaks the session is a security check people remove. It also means
the per-skill check allows rather than refuses there, which is the honest reading of exit 0.

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

### More than one client

Codex CLI installs the same plugins, from the same marketplaces, into the same layout —
`~/.codex/plugins/cache/<marketplace>/<plugin>/<version>`, `.claude-plugin/plugin.json` and
all — and reads hooks from JSON with the same shape under the same event names. So it is
checked the same way:

```bash
skillctl hook install --client codex --apply   # writes ~/.codex/hooks.json
skillctl sync --agent codex --report-only      # or check by hand
```

Two differences are worth knowing before you rely on it.

**Codex reviews hooks before it runs them.** It keeps a `trusted_hash` per hook in
`config.toml` and asks about anything it has not seen. Writing the entry is therefore not
the end of the job: until you approve it in Codex, nothing is checked. `skillctl` says so
after installing and deliberately does not write that hash itself — a tool that granted
itself execution inside another tool, past the review that client added on purpose, would
be doing the thing this project exists to catch. Approve the hook rather than reaching for
`--dangerously-bypass-hook-trust`, which turns the review off for every hook you have.

**There is no per-skill check, because Codex has no per-skill moment.** It does not route a
skill through a tool call: it lists every available skill — name, description, path — in the
developer message it builds when the session starts, and the model then reads the `SKILL.md`
itself. There is no `PreToolUse` matcher meaning "a skill is about to load", so none is
installed rather than one that never fires. In exchange the session-start check lands
earlier than on Claude Code: the bytes are put back before the model has seen the list at
all. What neither client gives is a re-check part-way through a session already running.

**Cursor is known here, and gets no hook.** It installs nothing from a marketplace — it has
no `plugins/cache` tree at all, so there is nothing for a check to put back or refuse, and an
entry at its session start would walk an empty directory and print the same nothing as a
machine where everything matched. Those two must not look alike, so none is installed:

```bash
skillctl hook install --client cursor    # says why, writes nothing
skillctl lint                            # reads ~/.cursor/skills and .cursor/skills
```

Cursor is worth listing anyway for two reasons. Its skill directories — `~/.cursor/skills`
and a repository's `.cursor/skills` — are now scanned like every other client's. And with
third-party extensibility on, its default, Cursor also loads `~/.claude/skills` and
`~/.codex/skills`, so a machine already set up for either of those is largely covered.

One thing it does that looks like more than it is: Cursor reads Claude Code's
`~/.claude/settings.json` and translates the hooks it finds — `SessionStart` to its own
`sessionStart`, `PreToolUse` matchers `Bash`, `Read`, `Write` and `Edit` to its own. So the
hook installed for Claude Code can also run inside Cursor. Do not count on it: that import is
gated on a flag that arrives in Cursor's server configuration rather than from any file on
your machine, and defaults to off. Whether it is on is not something this tool can observe,
and a check you cannot confirm is running is not a check.

**Antigravity CLI is known here, and also gets no hook.** It has plugins, and they are not
the plugins this tool reconciles. `agy plugin install` accepts `plugin@marketplace`, but what
lands on disk is `plugins/<name>/plugin.json` inside a customization root — no marketplace in
the path, no version, and the manifest at the directory root rather than under
`.claude-plugin`. Reconciling keys on marketplace, plugin and version, so it could not
identify an installed copy here. There is also no session-start moment: the events are
`PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation` and `Stop`, and the first two
run on every tool call rather than once.

What Antigravity does need is a scanner that can find its skills at all:

```bash
skillctl lint    # reads .agents/skills, ~/.gemini/config/skills,
                 # and every directory a skills.json registers
```

That last clause is the reason this client was worth adding. A repository can register skill
directories anywhere through `.agents/skills.json` — absolute, `~/`-relative, or relative to
the repository root — and committing one is the documented way a team shares skills. So the
set of directories the agent reads is a property of the machine rather than of any table
here, and a scanner that knew only the fixed paths would have told a team whose skills live
in `tools/agents/skills` that their machine was clean without ever opening the directory.
Configs that `inherit` from other configs are followed, because a shared config is how an
organisation distributes those paths.

One thing it does not do: `include_only` and `exclude` in a `skills.json` are not applied.
They are regular expressions over skill names inside a root, and this resolves roots. The
cost is scanning a skill Antigravity would skip, which is noise; the other error would be a
silent gap.

Loose skills are read from `~/.agents/skills` — the cross-client location Codex and Amp both
use — as well as each client's own `skills` directory. The search starts in the working
directory and climbs to the repository root, because that is what every client here does: a
check run from inside `server/` has to find the project's skills at the top of the checkout,
or it reports a clean machine having never looked at them. It stops at the root rather than
continuing, so a sibling checkout's skills are never counted as this one's.

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
  --key acme.pub --notary-key notary.pub
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
| `lint` | either | Inventory every skills directory and report risk indicators. |
| `digest` | either | The canonical digest of a skill directory. |
| `attest` | either | Sign and verify a statement about a digest. |

### Skills nobody publishes

Everything above is about plugins that come from a signed marketplace, and three of the four
clients supported here install nothing that way. For a skill written locally or committed to
a repository — which is what `.agents/skills`, `.cursor/skills` and a Cursor or Antigravity
machine is made of — the question "are these the bytes somebody approved?" has a separate
answer, and it needs no server:

```bash
skillctl attest sign ~/.agents/skills/deploy --store   # approve these bytes, keep the record
skillctl attest verify                                 # check every skill on this machine
```

`--store` keeps the approval in `~/.skilltrust/attestations` rather than only beside the
skill. That matters because an attestation living next to what it approves is deleted by
whatever deletes that thing, and `git clean`, a reinstall and a fresh clone all do exactly
that. `attest verify` with no argument reads both, so a copy that arrived carrying its own
attestation still verifies.

It prints one line unless something is wrong:

```
1 verified · 0 changed · 0 with no approval on this machine
```

Skills nobody approved are counted rather than listed. Most skills on a laptop are somebody's
own, and a check that treats each of them as a finding is one that gets run once — but
saying nothing at all would read as though they had been approved. A skill whose bytes no
longer match its approval is reported with both digests and exits non-zero. The digest is
recomputed from disk every time rather than read from the signed statement: a valid signature
over the wrong bytes is the failure this exists to catch.

## For the agent

Setting a machine up is a sequence in which every step succeeds out of order and the wrong
order fails silently — pinning after subscribing, or two pinned keys with a threshold of one.
`skilltrust-mcp` serves that sequence over the Model Context Protocol, so an agent follows it
rather than reconstructing it from this file.

```jsonc
{
  "mcpServers": {
    "skilltrust": { "command": "skilltrust-mcp" }
  }
}
```

It offers three things, and the tools are the least interesting of them:

- **Resources** — `skilltrust://state` says what is already set up and names the single next
  step, which is the question every setup starts with and no command answers. Alongside it:
  the machine's public key, the pinned set, the catalogs followed, and a written guide. The
  private key has no URI.
- **Prompts** — `set_up_this_machine`, `publish_this_repository`, `investigate_change`. The
  order and the reasons for it.
- **Tools** — thin wrappers over the commands below. `skilltrust_check` reports and writes
  nothing; `skilltrust_sync` is marked destructive because it restores files. Subscribing
  defaults the threshold to the number of keys pinned, which is where the CLI's default of
  one is a trap. `skilltrust_verify_skills` covers everything a marketplace does not: it is
  the only tool here that answers "are these the approved bytes?" for a skill that arrived
  from a repository or a copy, which on Cursor and Antigravity is all of them.

It is a separate binary on purpose. `skillctl` decides whether a skill is trusted and runs at
every session start; the MCP SDK brings nine dependencies, and a verifier whose supply chain
grows to serve a convenience is arguing against itself. `go version -m` on a built `skillctl`
still lists two.

Registering an organisation with a hosted notary is not among the tools, because it happens
in a browser behind a sign-in and returns tokens shown once. The prompt says so and hands
that step to a person.

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

Line endings are part of the identity for the same reason, and git rewrites them by
default: `core.autocrlf` is `true` on a stock Windows install, so the same commit checks
out as different bytes there. Publishers should pin them in the marketplace repository —

```
# .gitattributes
* -text
```

— and `skillctl lint` reports CRLF as `portability/crlf-line-endings`, because the failure
it causes is a quarantine on a machine that did nothing wrong, which is the kind of false
alarm that teaches people to switch the check off.

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
serving, event collection, OIDC publishing, a read-only web console), `fleet` over a
directory or the notary, `lint`, `digest`.

Not built here: registration, multi-tenancy, billing. `notaryd` serves the organisations
its configuration names and is meant to be run by the people it serves — a hosted service
on top of it is a different product, and [Axela](https://axela.app) is ours. Nothing about
verification lives there: it implements the `Storage` and `Directory` seams and imports
this module, and `notarytest.Contract` is the suite any implementation of those seams
should pass.

## Layout

```
action.yml     the GitHub Action that runs the gate and talks to the notary
client/        skillctl — the CLI. One static binary, two dependencies.
server/        notaryd — the notary. Same story: one binary, files for state.
internal/      the packages both sides are built from: digest, DSSE, catalog, reporting
plugin/        the Claude Code plugin: hooks, and the binary shim that finds skillctl
docs/          the threat model, key rotation, running the gate in other CIs,
               and what a review panel does when the account is throttled
```

The Go module lives at the root so that the notary service and the client verify with the
same code. Two implementations of a digest agree until the day it matters; this layout
makes a second one impossible to add by accident.

There was once a Python control plane here, and documents describing four trust layers, a
private ACME CA and a transparency log. None of it was built. It was removed rather than left
to imply the product does things it does not — an architecture document nobody implemented is
read as a specification, and this one would have been read as a promise.

## Licence

Apache-2.0; see [LICENSE](LICENSE). All of it — the CLI, the libraries and the notary
server. The verification path must be auditable and rebuildable by the people it asks to
trust it, and a self-hosted notary is a supported deployment, not a crippled demo.

The hosted service built on this code is **Axela** (https://axela.app): registration,
multi-tenant operation and the console as a service. That part is not in this repository.
