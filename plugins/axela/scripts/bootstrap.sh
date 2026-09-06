#!/bin/bash
set -euo pipefail

fail() { printf 'Axela: %s\n' "$*" >&2; exit 2; }
if [[ ${1:-} == --help ]]; then
  printf '%s\n' 'Usage: bootstrap.sh <CLAUDE_PLUGIN_DATA>' \
    'Prepare the checksum-pinned Axela release in this user-owned plugin data directory.' \
    'Print its absolute path. A verified cached binary works offline.' \
    'Requires Bash, curl, tar (Linux) or unzip (macOS), and sha256sum or shasum.'
  exit 0
fi
[[ $# == 1 ]] || fail 'Expected the Claude plugin data directory; run /axela:doctor.'

plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) platform=linux_amd64; format=tar.gz ;;
  Linux:aarch64|Linux:arm64) platform=linux_arm64; format=tar.gz ;;
  Darwin:x86_64|Darwin:arm64) platform=darwin_universal; format=zip ;;
  *) fail 'This entry supports macOS and Linux on x86-64 or ARM64; this platform needs a supported release installer.' ;;
esac

version= archive_hash= binary_hash=
while read -r release_version release_platform release_archive_hash release_binary_hash extra; do
  [[ -z "$release_version" || "$release_version" == \#* ]] && continue
  [[ "$release_version" != UNRELEASED ]] || fail 'This development plugin has no published Axela release pinned yet. Ask its maintainer to complete the release gate; no download or skill check ran.'
  [[ -z "$extra" && "$release_version" =~ ^[0-9][0-9A-Za-z.+_-]*$ && "$release_archive_hash" =~ ^[0-9a-f]{64}$ && "$release_binary_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'The bundled release lock is malformed; reinstall an approved Axela plugin.'
  [[ "$release_platform" == "$platform" ]] || continue
  [[ -z "$version" ]] || fail 'The bundled release lock has duplicate platform entries.'
  version=$release_version; archive_hash=$release_archive_hash; binary_hash=$release_binary_hash
done < "$plugin_root/release.lock"
[[ -n "$version" ]] || fail 'The bundled release lock has no artifact for this platform.'

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { local value; value=$(sha256sum < "$1") || return; printf '%s' "${value%% *}"; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { local value; value=$(shasum -a 256 < "$1") || return; printf '%s' "${value%% *}"; }
else
  fail 'A SHA-256 utility is required; install sha256sum or shasum through your approved system tools.'
fi

data=${1%/}
[[ "$data" == /* && "$data" != / ]] || fail 'Claude plugin data must be an absolute user-owned directory.'
[[ "$data/" != */../* ]] || fail 'Claude plugin data must not contain parent-directory traversal.'
umask 077
for directory in "$data" "$data/runtime" "$data/runtime/$version" "$data/runtime/$version/$platform"; do
  [[ ! -L "$directory" ]] || fail 'Axela runtime storage must not be a symbolic link.'
  mkdir -p -- "$directory" || fail 'Cannot create the Axela runtime in Claude plugin data.'
  [[ -d "$directory" && -O "$directory" ]] || fail 'Axela runtime storage must belong to the current user.'
done
storage="$data/runtime/$version/$platform"
binary="$storage/axela"

validate_binary() {
  [[ -f "$1" && ! -L "$1" && -x "$1" ]] || fail 'The pinned Axela binary is missing or not executable; no skill check ran.'
  [[ "$(hash_file "$1")" == "$binary_hash" ]] || fail 'The Axela binary failed its pinned SHA-256 check; no skill check ran.'
  local magic
  magic=$(od -An -tx1 -N4 "$1" | tr -d ' \n')
  case "$platform:$magic" in
    linux_*:7f454c46|darwin_*:cafebabe|darwin_*:bebafeca|darwin_*:cffaedfe|darwin_*:feedfacf) ;;
    *) fail 'The pinned payload is not a native Axela executable; scripts cannot stand in for the verifier.' ;;
  esac
  "$1" doctor --help >/dev/null 2>&1 || fail 'The pinned Axela binary cannot run doctor here; check executable-storage policy and the release compatibility.'
}

if [[ -e "$binary" || -L "$binary" ]]; then
  validate_binary "$binary"
  printf '%s\n' "$binary"
  exit 0
fi
command -v curl >/dev/null 2>&1 || fail 'curl is required for the first download; install it through your approved system tools.'
stage=$(mktemp -d "$storage/.download.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
archive="skillctl_${version}_${platform}.${format}"
url="https://github.com/random1st/skilltrust/releases/download/v${version}/${archive}"
if ! curl -q --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 60 --output "$stage/archive" "$url"; then
  fail 'The pinned release could not be downloaded. Check connectivity, HTTPS_PROXY and the approved corporate CA configuration, then retry /axela:doctor. TLS verification remains required.'
fi
[[ "$(hash_file "$stage/archive")" == "$archive_hash" ]] || fail 'The download failed its pinned SHA-256 check; no downloaded program ran.'
case "$format" in
  tar.gz) tar -xzf "$stage/archive" -C "$stage" -- axela || fail 'The pinned release archive could not be unpacked.' ;;
  zip) unzip -qq "$stage/archive" axela -d "$stage" || fail 'The pinned release archive could not be unpacked.' ;;
esac
validate_binary "$stage/axela"
# Concurrent first runs may download twice. Each publishes the same fully checked
# bytes with one atomic rename; no caller can observe a partially written binary.
mv -f -- "$stage/axela" "$binary"
printf '%s\n' "$binary"
