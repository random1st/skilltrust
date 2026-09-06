# Axela plugin entry

This is a **local development entry**, not an installable public release. The
checked-in `plugins/axela/release.lock` says `UNRELEASED`: `/axela:doctor` stops
before creating runtime state, downloading anything, or claiming a check ran.
Release 0.4.2 does not provide this entry's `axela doctor` contract. Existing public
installation instructions remain the supported route until the release gate below
is completed.

## The first interaction

The intended first 30 seconds after installation are: invoke `/axela:doctor`, see
which installed skills were found and their verdicts, and receive one concrete next
command. There is no account or publisher selection before this first observation.
An unapproved skill leads to reviewing its exact path with lint; review does not
approve it. An empty inventory is not a verified machine. First-download duration
depends on the network; a 30-second end-to-end timing claim needs a measured release
test.

After the release is enabled and the publisher's marketplace is registered, the
native user flow is:

1. `/plugin install axela@<the registered marketplace name>`.
2. `/reload-plugins` if Claude asks for activation.
3. `/axela:doctor`.

The marketplace name is supplied by the publisher; this document does not invent
a public registration. The command is deliberately user-invoked. It runs a bundled
script through Claude's dynamic skill context, before the model summarizes the
result. It does not depend on the model guessing an onboarding phrase.

## Runtime contract

`skills/doctor/SKILL.md` passes Claude's substituted `CLAUDE_PLUGIN_DATA` path to
`scripts/doctor.sh`. The allowed-tools rule names that same script and argument.
An explicit deny or a managed policy disabling skill shell execution still wins.
This is a Claude Code plugin, not a claude.ai synced skill.

The bootstrap reads the bundled lock as data. Each platform row contains:

```text
version platform archive_sha256 axela_binary_sha256
```

Supported platforms are `linux_amd64`, `linux_arm64` and `darwin_universal`.
Linux uses the release's `tar.gz`; macOS uses its notarized `zip`. Windows needs a
separately tested entry and is currently rejected. Asset URLs are derived from the
exact version at `random1st/skilltrust`; neither `latest`, an environment URL
override, nor a fetched checksum can change the bundled pins.

The real native executable lives at:

```text
${CLAUDE_PLUGIN_DATA}/runtime/<version>/<platform>/axela
```

There is no `bin/`, PATH modification, `skillctl` wrapper, system installation,
credential copying, or trust-key creation. Existing user-owned runtime bytes must
still match their pinned digest and be executable. Fresh downloads are checked in
a private temporary directory before one atomic rename publishes them. Concurrent
first runs can fetch the same artifact more than once; they cannot activate partial
bytes. Staging directories are removed on normal exit.

The first download uses curl's standard `HTTPS_PROXY` and `CURL_CA_BUNDLE`
configuration, with HTTPS-only redirects and TLS verification. It does not use
Homebrew or disable certificate checks. A verified cached binary works offline.
Transport, checksum, executable-storage and unsupported-release errors stop the
invocation with diagnostics. A damaged cached runtime is preserved and rejected;
it is not silently executed or trusted anew.

The wrapper runs only `axela doctor --json --absolute-commands`. Its next-command
arguments use the already verified executable's full path, so the first suggested
action does not require a second installation on PATH. Doctor exit codes 0 and 1 become
`{"doctor_exit_code": ..., "result": ...}` so a finding remains visible to Claude.
Other exit codes remain command failures. There is no unconditional `|| true`.
On a machine already following a catalog, doctor retains its existing
`status --refresh` behavior. On a clean machine, its inventory observation does not
create approvals or keys.

## Local checks and native proof

From the repository root:

```sh
bash -n plugins/axela/scripts/bootstrap.sh plugins/axela/scripts/doctor.sh
claude plugin validate --strict --json ./plugins/axela
go test -race ./internal/pluginentry -count=1
```

The Go tests use owned temporary directories, a native compiled fixture executable
and a mock curl transport. They exercise corruption, offline and proxy behavior,
non-executable files, exit-code preservation, concurrent bootstrap and current-user
storage. They do not override HOME, install a plugin into the host, or call a model.

For native testing, load an owned copy through the documented session-only flag:

```sh
claude --plugin-dir /absolute/path/to/owned/axela
```

Then invoke `/axela:doctor`. The checked-in disabled lock should show its explicit
release-gate error. To prove the enabled transport locally, use an **owned copy**
with a fixture lock, a freshly built real CLI and mock artifact transport. Build
with the canonical target:

```sh
make -C client build VERSION=0.0.0-local-proof BIN_DIR=/absolute/path/to/owned/build
```

Package that copy of `axela` in the platform's release archive format, pin its
archive and executable hashes in the copied lock, and make the mock curl serve only
that archive for the exact derived fixture URL. Keep the checked-in lock disabled.
Use a disposable ordinary-user container for native registration, runtime writes
and slash invocation. Do not copy host credentials or change HOME to simulate an
isolated user. Record native discovery and shell-injection output separately from
an authenticated model response: manifest validation alone proves neither of them.
Local build and transport evidence does not establish that an artifact was published.

## Release enable procedure

1. Select a new immutable CLI release version containing the real `axela` binary
   and `doctor --json`. Run the canonical `make check`, `make plugin` and release
   checks. The authorized maintainer publishes with `make -C client release`;
   macOS signing and notarization stay in that existing procedure. Do not rewrite
   0.4.2 or point this entry at it.
2. Retrieve all three published assets and the release checksum file. Verify each
   archive against the published checksum, extract only `axela`, confirm its native
   format and executable mode, and run `axela doctor --help` on the supported host.
   Record SHA-256 for both the complete archive and extracted executable. Replace
   `UNRELEASED` with exactly one row for each supported platform, using that actual
   release version. Review the resulting lock as part of the plugin's code.
3. Give the plugin its chosen release version and remove the development-only
   description. Validate it natively. Test download, repeat offline invocation and
   `/axela:doctor` on clean supported users with the **published bytes**; retain the
   doctor JSON, exit code and elapsed time. Complete the module's canonical checks.
4. Copy that reviewed plugin snapshot into `plugins/axela` in the publisher's
   marketplace checkout. Register `name: axela` with local `source: ./plugins/axela`
   and its exact plugin version in the native marketplace manifest. Keep the
   existing hooks-only plugin's registration and bytes intact. A remote source
   outside the publisher's owned tree would not be covered as its own signed bytes.
5. With authorization and the **existing approved publisher key**, sign and verify
   the updated catalog using the documented commands:

   ```sh
   skillctl marketplace sign "$axela_publisher_repo" --key "$axela_existing_signing_key"
   skillctl catalog verify "$axela_publisher_repo" --key "$axela_publisher_repo/catalog.pub"
   ```

   The two variables designate the actual publisher checkout and existing key path;
   the private key is not copied into the plugin, printed, or replaced. If that key
   is unavailable, stop this release gate. A new key is a separate explicit trust-root
   decision, not a bootstrap fallback. Complete the publisher's `skills-check`
   procedure and native clean-install verification before publishing the registration
   or changing the public first-install CTA.

Claude's official references cover [plugin layout and local loading](https://code.claude.com/docs/en/plugins),
[persistent plugin data](https://code.claude.com/docs/en/plugins-reference#persistent-data-directory),
and [skill substitution, permissions and injected-command failure behavior](https://code.claude.com/docs/en/skills).
