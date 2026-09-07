# Updating skillctl

```
skillctl update            # install the latest release
skillctl update --check    # say whether one exists; exit 1 if so
skillctl update --auto on  # let the session-start hook install verified releases itself
```

## What the updater trusts

A verifier that updates itself is the most valuable target on the machine, so the rule is
that the binary accepts only what the **release key** signed — never what the download
host served.

1. `releases/latest` names a version (a redirect; nothing about it is trusted).
2. `skillctl_<v>_checksums.txt.dsse.json` is fetched and verified against the release
   public key compiled into the binary (`client/cmd/skillctl/update_key.go`). The
   checksums are read out of the verified envelope, never from a separate download.
3. The archive for this platform is fetched and must match its signed checksum.
4. The new `skillctl` is run with `--version` and must name the version it claims.
5. Only then is the running binary replaced — by a rename, so there is no moment with
   half a binary in place. `axela` and `skilltrust-mcp` beside it are replaced too, if
   they are installed; nothing that was not installed is introduced.

A "latest" that is older than what is installed is a rollback, not an update, and is
never applied. Development builds (`skillctl version` says `dev` or a pseudo-version)
never update.

## Homebrew

A Homebrew install belongs to Homebrew: replacing the file under its prefix would leave
`brew` believing it manages a version it does not. On those installs `skillctl update`
runs `brew upgrade --cask random1st/tap/skillctl` instead.

## The session-start hook

By default the hook only *says* that a release exists — one line, at most one lookup a
day, two seconds at most, and silence on any failure. It does not rewrite the binary:
a verifier that silently replaces itself when a session starts is exactly what a
security review flags first.

`skillctl update --auto on` opts a machine into installing verified releases from the
hook. `SKILLTRUST_NO_UPDATE_CHECK=1` disables the lookup entirely (fleets that pin
versions, CI).

State lives in `$SKILLTRUST_HOME/update.json`: when the host was last asked, what it
said, and the auto preference.

## Releasing

`make release` refuses to run without `RELEASE_SIGNING_KEY`, the path to the release
private key. goreleaser signs the checksums file with it (`tools/release-sign`) and
uploads `…_checksums.txt.dsse.json` beside the archives. The key lives on the release
machine outside every repository; rotate it by shipping a release signed by the old key
whose binary embeds the new public half, then switching the signer.
