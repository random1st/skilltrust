# Threat model

What this defends against, what it does not, and where the line is. It describes the product
as built; an earlier version of this file described a system with TUF roots, a private ACME
CA and a transparency log, none of which exists, which is worse than having no threat model
at all.

## What is being protected

The bytes of a plugin between the moment its publisher signed them and the moment Claude Code
follows them with a developer's credentials.

Not the developer's machine, not the network, not the git host. Those are other people's
problems and pretending otherwise is how a security tool gets believed about things it cannot
see.

## Adversaries this addresses

**An agent editing a plugin it can write to.** The case the product exists for. An agent has
write access to the plugin cache and can edit a `SKILL.md` so an injected instruction survives
the session. Detected on the next session start, and in the moment before the skill loads;
the bytes are restored and the edit is kept in quarantine.

**Someone editing an installed plugin by hand.** Indistinguishable from the above and handled
identically. The tool does not attempt to say who.

**A withdrawn or compromised plugin still installed.** Revocation is keyed by digest, so it
follows the bytes through a rename, a move or a copy, and it outranks a valid signature —
a signature is a statement about the past and a revocation about now.

**A replayed catalog.** A monotonic sequence means a machine that has seen N refuses N-1, so
an old catalog cannot be served to un-revoke something. Expiry means a stale catalog is a
refusal rather than an answer of "nothing revoked".

**A publisher key that is not the one you pinned.** An index must be signed by the key pinned
for that marketplace specifically, not merely by a key the machine trusts, or one publisher
could speak for another's plugin names.

**A repository whose contents no longer match its signature.** The catalog is signed and the
repository is not: bytes in a checkout that the index does not name are refused rather than
installed because the URL was right. CI fails a pull request that changes a plugin without
republishing.

**A forged fleet report.** Events are signed by the machine that filed them; a report no
trusted machine signed is refused rather than counted.

## Adversaries this does not address

**Anyone who can write to the policy.** Managed settings are the enforcement boundary. Root on
the machine, or control of the MDM that deploys them, is outside this entirely.

**A compromised signing key.** Nothing here detects that the right key signed the wrong thing.
A notary countersignature raises the cost of using a stolen key — see below — but it does not
close this: the notary checks who signed, never what they signed.

**A compromised git host or CI.** Whoever can push to the marketplace and hold the signing key
can publish whatever they like. With a notary the attacker needs the publish credential too,
which is a second thing to steal rather than a second opinion about the contents.

**Prompt injection reaching the agent by any other route.** A verified plugin is a plugin
whose bytes someone approved. It is not a plugin that is safe: no static check can certify
prose an agent will follow, and `lint` reports indicators for a human rather than a verdict.

**Dependency code installed after fetch.** `node_modules` is excluded from a plugin's identity
because the client installs it, so a plugin carrying dependencies is reported as *partially*
covered. That code is real and nobody signed it.

**A plugin hosted outside the marketplace.** A publisher cannot vouch for bytes they do not
control, so remote-sourced entries are named and explicitly not signed.

## What a notary changes, and what it does not

A notary countersigns catalogs a registered publisher signed. Machines that pin both keys and
require two signatures get a specific, bounded improvement — worth stating precisely, because
"two signatures" invites believing more than it delivers.

**It does not review anything.** The notary verifies *who* signed, never *what*. A stolen
publisher key used with the publish credential produces a catalog the notary countersigns
without hesitation, because from where it stands nothing is wrong. This is not a second
opinion; it is a second lock on the same door.

**A compromised notary alone publishes nothing.** It can countersign, and it cannot produce
the publisher's signature. A machine requiring two refuses what only the notary signed. This
is the property the design exists for and the reason the notary is deliberately not a trust
root.

**A stolen publisher key alone publishes nothing either**, to machines that fetch the catalog
from the notary. The attacker also needs the publish credential — or the registered
repository's CI, when OIDC publishing is enabled. Two things to steal instead of one.

**Rollback protection becomes central.** The notary refuses a sequence below what it recorded,
so a replay is stopped before it reaches any machine rather than by each machine separately.

**It is not on the verification path.** Machines verify from the catalog already on disk; the
network is for refreshing. A notary that is down, unreachable or hostile cannot make a machine
accept anything — at worst it stops delivering updates, and staleness is a refusal.

**The mailbox is not a trust root.** The notary stores the events machines file without
verifying their signatures — it has no registry of machine keys, and inventing one would make
the mailbox authoritative about who reported what. `skillctl fleet` and the console verify
against keys the administrator pinned, and count the rest as unverified rather than showing
them as evidence.

**What a hosted notary sees.** Which organisations publish which marketplaces, when, and what
their machines report. Not skill contents beyond what the catalog names, and never a
publisher's private key. An operator of a shared notary is trusted with that metadata, which
is a reason to run your own — `notaryd` is the same code.

## The line

Without a managed policy this is detection: the hook is a convention, and a convention can be
edited by whoever can edit the thing it guards. Claude Code also documents that a hook which
times out does not block.

With a managed policy — a file in a system directory the developer cannot write to, forcing
the plugin on and permitting only managed hooks — the check cannot be removed by the machine
it checks. That is the one place the word enforcement is used here, and it is used nowhere
else on purpose.

## Known limitations, pinned by tests rather than footnotes

Windows has no executable bit and the bit is part of a plugin's identity, so a plugin
containing executables does not produce the same digest there.

A time-of-check to time-of-use gap remains: the check runs before a skill loads, and nothing
prevents a write between the two. Closing it would need the client to hold a lock this tool
cannot ask for.
