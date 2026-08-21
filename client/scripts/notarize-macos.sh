#!/bin/sh
# Submit the macOS release archives for notarization.
#
# Runs after publishing on purpose. A bare CLI binary cannot be stapled — only .app, .dmg
# and .pkg carry a ticket — so notarization registers the archive's hash with Apple and
# Gatekeeper looks it up online. Because that lookup is by hash and the bytes never change,
# submitting after upload is equivalent to submitting before it, and it keeps the release
# itself from blocking on Apple's queue.
set -eu

directory="${1:-dist}"
profile="${NOTARY_PROFILE:-notarize-diana}"

if ! command -v xcrun >/dev/null 2>&1; then
    echo "notarize-macos: xcrun unavailable; this must run on macOS" >&2
    exit 1
fi

# Fail rather than silently skip: a release that reports success while notarizing nothing
# is the same class of defect as a lock file that cannot be read being treated as absent.
if ! xcrun notarytool history --keychain-profile "${profile}" >/dev/null 2>&1; then
    echo "notarize-macos: keychain profile '${profile}' is not usable." >&2
    echo "  Create it once with: xcrun notarytool store-credentials ${profile}" >&2
    exit 1
fi

found=0
for archive in "${directory}"/*darwin*.tar.gz; do
    [ -e "${archive}" ] || continue
    found=$((found + 1))
    echo "notarize-macos: submitting ${archive}"
    xcrun notarytool submit "${archive}" --keychain-profile "${profile}" --wait
done

if [ "${found}" -eq 0 ]; then
    echo "notarize-macos: no darwin archives in ${directory}" >&2
    exit 1
fi

echo "notarize-macos: ${found} archive(s) accepted"
