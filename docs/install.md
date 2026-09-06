# Install Axela

The local development build provides `axela doctor` for a first verdict on already
installed skills without an account. `skillctl` remains a compatible command name.
Build and check this checkout with:

```sh
make check
make -C client build mcp
client/bin/axela doctor
```

The [Claude plugin entry](plugin-entry.md) provides `/axela:doctor` and fetches a
pinned native executable into user-owned plugin storage, independently of Homebrew.
Its release lock is deliberately disabled until a new CLI release and signed
marketplace registration exist. Release **0.4.2** below does not include `axela`,
`doctor`, or the new URI subscription. Do not use its bytes to enable the plugin.

## Existing release 0.4.2

Install both commands, `skillctl` and `skilltrust-mcp`. They ship together. Git is
required to follow a publisher's repository. Install Claude Code or Codex first if
you want its MCP integration or session checks.

## macOS

```sh
brew install random1st/tap/skillctl
skillctl version
```

## Linux

The block below selects x86-64 or ARM64, downloads release **0.4.2**, checks the
archive against its published SHA-256 checksum, and installs both commands in
`~/.local/bin`. It needs `curl`, `tar`, `sha256sum`, and `install`.

```sh
(
  set -eu
  case "$(uname -m)" in
    x86_64) release_arch=amd64 ;;
    aarch64|arm64) release_arch=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  release_version=0.4.2
  release_url="https://github.com/random1st/skilltrust/releases/download/v${release_version}"
  release_archive="skillctl_${release_version}_linux_${release_arch}.tar.gz"
  release_tmp=$(mktemp -d)
  cd "$release_tmp"
  curl -fSL "$release_url/$release_archive" -o "$release_archive"
  curl -fSL "$release_url/skillctl_${release_version}_checksums.txt" -o checksums.txt
  sha256sum --check --ignore-missing checksums.txt
  tar -xzf "$release_archive" skillctl skilltrust-mcp
  install -d "$HOME/.local/bin"
  install -m 0755 skillctl skilltrust-mcp "$HOME/.local/bin/"
)
export PATH="$HOME/.local/bin:$PATH"
skillctl version
```

If `~/.local/bin` was not already on PATH, keep that `export` line in your shell's
startup file so a new terminal can find the commands. The temporary download
directory is left under the system's temporary directory for inspection.

## Windows

Download the Windows archive for your architecture from the
[release page](https://github.com/random1st/skilltrust/releases/latest). Extract
`skillctl.exe` and `skilltrust-mcp.exe` into the same directory, then add that
directory to your user PATH. Open a new terminal and run `skillctl version`.

## First check

See the full detect-and-restore demonstration in its own sandbox:

```sh
skillctl demo
```

To use MCP, run `skillctl setup`, restart your agent, and ask it to help you follow
signed skills without an account. Give it a publisher's repository and public key,
or use the [public starter instructions](https://github.com/random1st/axela-skills#install-verified).
Your team can instead use `skillctl connect` for browser-approved Axela setup.

Installing the commands or connecting MCP does not itself verify any installed
skill. Finish with a nonempty check and the session hook installed. An expired
catalog needs its publisher's renewal before this can succeed.

## Development subscription and recovery

For a public or team catalog, the new build accepts one identifier:

```sh
axela subscribe axela://their-org/their-skills
axela doctor
```

The local server implementation must be released before that URI is available at
the fixed public origin. Publisher and notary identity, the exact source commit and
catalog bytes are checked before any local trust is saved. A later attempt cannot
silently replace an established pin or commit over a concurrent trust change.

Public sharing requires the owner's consent. For team access, the same URI reuses
this computer's matching Axela identity, or opens browser approval for that team.
That approval grants catalog access; it does not configure reports, install hooks,
or follow other catalogs. A computer already connected to another team keeps that
connection and reports the conflict.

The team owner registers the repository and grants the Axela GitHub App access.
Axela delivers the marketplace and its local plugin trees at the signed commit;
the consumer needs no GitHub token, SSH setup, or manual key files. Publisher and
notary signatures remain independent. Each private refresh and install checks
current membership and machine access, including when source files are cached.
Denied or offline access cannot authorize a new install or automatic recovery.
Already downloaded files remain on the computer.

Hosted catalog reads are now closed unless the catalog has proven source visibility
and either public owner consent or current team authorization. Existing hosted
subscriptions need an explicit URI upgrade; catalogs lacking source provenance need
a fresh GitHub Actions publication. Roll out compatible server and client versions
together. The standalone notary retains its anonymous catalog API, so private Git
credentials alone do not make a self-hosted catalog confidential.

Source delivery is limited to 4 MiB compressed and the existing canonical plugin
file and expanded-size limits. Unrelated files outside subdirectory plugins are
excluded. A marketplace plugin with source `.` publishes root content under the
existing canonical exclusions; keep unrelated confidential files outside that
plugin's tree. Missing files or unsupported links within a local plugin stop
delivery instead of producing a partial source.

Run `axela doctor` after setup or when a session reports a problem. It prints the
checked state and a concrete next command. For saved edits, use the exact `diff`
command it prints, including its saved path and version. The diff compares content,
binary digests and file modes, and emits a digest-bound `adopt` command when that
copy still belongs to the current version. After a publisher upgrade it permits
review but requires reapplying the edit to the current version before approval.
It does not substitute the saved old version for the new published version.

Claude hook warnings contain a visible `systemMessage` and agent context. To keep a
saved-change marker in a custom status line, compose `axela statusline` into the
existing script. Axela does not overwrite an existing corporate status line.
Use `axela policy --from export.json --diff ...` to review a proposed MDM merge;
the MDM owner applies it through their existing management process.
