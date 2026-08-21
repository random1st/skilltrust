# SkillTrust

**Prove that the bytes your agent loads are the bytes someone approved — and notice when
they stop being.**

An [Agent Skill](https://agentskills.io/specification) is a folder whose `SKILL.md` an agent
reads and follows, with your credentials. Skills spread by `git clone` and copy-paste, so
three questions have no answer today: what is actually in them, has anything changed, and did
anyone approve it.

`skillctl` answers all three, offline, in under a minute.

## Quickstart

```bash
skillctl lint ~/.claude/skills     # what is in there, and what reaches for credentials
skillctl lock ~/.claude/skills     # pin every skill by digest
skillctl verify ~/.claude/skills   # has anything changed since?
```

No account, no key, no network. `lint` runs on a tree you already have.

## Why the lock matters for your own skills

An agent that can write files can edit its own `SKILL.md` so an injected instruction survives
the session. Nothing else notices: the edit is made by a legitimate process with legitimate
permissions and reads as ordinary work. A pinned digest notices, and names the file:

```
  modified   bug-fix-protocol
             pinned   sha256:3727dd404ca5…
             on disk  sha256:bc2ffd3afa74…
               modified     SKILL.md
```

It also catches the change that leaves content untouched — a file that became executable,
moving a skill out of the instruction-only tier without a single character changing.

Wire it into your client so the check runs when it matters:

```bash
skillctl hook install            # prints the configuration
skillctl hook install --apply    # writes it, keeping a backup
```

The hook prints nothing when everything matches. Silence when clean is deliberate: a hook that
speaks every session is one people stop reading.

## Commands

| Command | What it does |
| --- | --- |
| `lint` | Specification conformance plus risk indicators. Text, JSON or SARIF. |
| `digest` | The canonical digest of a directory. No source-control arguments, so a second party can re-derive it. |
| `lock` | Pin every skill under a path into `skills.lock`. |
| `verify` | Recompute and report drift. `--frozen` also fails on unpinned skills; use it in CI. |
| `hook` | Run or install the session-start drift check. |
| `attest` | Sign an approval over a skill's digest, and verify one against pinned keys. |
| `catalog` | Revoke digests in a signed, expiring snapshot. |
| `sync` | Reconcile installed skills against the catalog and their receipts; `--prune` removes revoked ones. |
| `bundle` | Write a skill's canonical archive for distribution. |
| `install` | Verify a bundle against an attestation and install it, writing a receipt. |
| `receipts` | List what was installed, from where, and on whose approval. |

Exit codes are part of the contract: `0` clean, `1` findings or drift, `3` error. "We checked
and it is bad" and "we could not check" are different facts and never share a code.

## Installing

```bash
skillctl bundle skills/pdf-tools --out pdf-tools.tar
skillctl attest sign skills/pdf-tools --key signer.key --as reviewer@corp
skillctl install pdf-tools.tar --into ~/.agents/skills --attestation pdf-tools.att.json
```

`install` refuses without `--attestation` unless you pass `--unverified`, which the receipt
then records permanently — the safe path should not be the quiet one. The bundle is extracted
beside the destination and re-packaged to the digest that was verified before anything lands
under a name a client will read, so a failed install leaves the tree untouched.

Extraction is where a signature stops covering anything, so every guard applied when packing
is applied again when unpacking: path traversal, absolute paths, symlinks, duplicate members,
case and Unicode collisions, headers that lie about their length, and size limits.

## Revocation

A signature says these bytes were approved. Revocation says this digest is no longer allowed
*now*, and a claim about the present cannot be proved once and cached forever:

```bash
skillctl catalog revoke sha256:… --key signer.key --reason "credential exfiltration"
skillctl sync ~/.claude/skills --prune
```

The catalog carries a monotonic sequence and an expiry. Replaying an older catalog to
un-revoke something is refused even though its signature is genuine, and a stale catalog is a
refusal rather than an answer of "nothing revoked". Revocation is keyed by digest, so it
follows the bytes through a rename, a move, or a copy.

## The whole picture

`sync` answers four separate questions about every skill on disk, because collapsing them
into pass/fail throws away the part that says what to do:

```
  revoked    alpha        # in the revocation catalog
  drifted    beta         # changed since it was installed
  unmanaged  delta        # nobody installed it through skillctl
  unapproved gamma        # installed with --unverified

4 checked · 1 revoked · 1 drifted · 1 unmanaged · 1 unapproved
```

`--managed` makes unmanaged and unapproved failures too, which is the mode for a fleet you
control. Without `--catalog`, revocation is not checked and `sync` says so rather than
letting "no catalog configured" read as "nothing revoked".

## What this does not claim

**A clean report is not a safety verdict.** `lint` reports indicators for a human to read. No
static check can certify prose that an agent will follow.

**The hook is detection, not enforcement.** Anything able to edit a skill can edit the hook
that checks it. Real enforcement needs a boundary the developer does not own — CI, or
OS/MDM-managed configuration. On a laptop this tells you what happened; it does not prevent it.

**CI is where the check binds.** An ephemeral runner is the one environment where the author of
the change under review has no privileges. See `.github/workflows/skills-check.yml`.

## Verifying the tool itself

Builds are reproducible: `-trimpath`, a pinned toolchain, a commit-derived timestamp.

```bash
cd client && make reproducible    # two independent builds, compared
```

Rebuild a release from its tag and compare digests rather than taking our word for it. A
verifier you cannot rebuild is a verifier you have to trust, which is the thing this exists to
avoid. Releases are checksummed, SBOM'd and cosign-signed; the verification command ships in
each release's notes.

macOS builds are signed and notarized from the maintainer's machine, not from CI. Putting the
Developer ID key into a CI secret would place the key that signs every release wherever the
runner lives — for this product in particular, that is the weakest link available.

## Licence

Proprietary; see [LICENSE.txt](LICENSE.txt). The model is deliberately undecided: a licence
can be widened later, but source released under an open one cannot be withdrawn from anyone
who already has it.

## Status

Working today, tested on Linux, macOS and Windows: `lint`, `digest`, `lock`, `verify`, `hook`, `attest`, `catalog`, `sync`.
Signing is ed25519 with a locally held key; keyless Sigstore belongs behind the same interface
later, as the low-friction path for public skills.

Not built yet: distribution. There is no registry, no hosted notary and no way to fetch a
catalog other than putting the file where the client can read it. The Python tree under
`src/skilltrust/` is the control plane those will be built from — EKU-separated certificate
profiles, a fail-closed admission decision, SLSA provenance, Git review adapters bound to an
exact repository and head SHA — but none of it is wired to the client yet.

Two known limitations, both pinned by tests rather than footnotes. Windows has no executable
bit, so a skill containing executables does not produce the same digest there as on POSIX —
the bit is part of the identity on purpose, and a platform that cannot store it cannot
reproduce the digest. And Windows file modes are synthesized from the read-only attribute
rather than reflecting the ACL, so the owner-only check on a signing key does not run there;
protecting the key is the ACL's job and this tool does not inspect ACLs.

## Layout

```
client/          skillctl — the Go client. Single static binary, two dependencies.
src/skilltrust/  control plane: certificates, admission, provenance, storage (Python)
schemas/         JSON Schemas for the wire contracts
docs/            threat model, security specification, trust-model ADR
profiles/        example trust policies
```

The canonical archive format has exactly one implementation, in Go. The Python one is retired
and refuses to run without an explicit opt-in: the two disagree in ways that stay invisible
until a signature fails to verify in production.

## Development

```bash
cd client && make check                    # gofmt, vet, race tests, coverage
make setup && make check                   # the Python control plane
uv run skilltrust-admin --help             # control-plane CLI
```

See [the trust model](docs/architecture/0001-trust-model.md) and
[the security specification](docs/security-specification.md) before deploying anything.
