#!/bin/sh
# Sign a macOS binary with the Developer ID identity in the local keychain.
#
# GoReleaser's notarize block wants the certificate as a base64 blob, which means
# exporting the private key and handing it to a CI provider. For a product whose pitch is
# supply-chain integrity that is the weakest possible link: the key signing every release
# would live wherever the runner lives, and a compromised runner could sign anything as us.
# Signing here keeps the key in the keychain it was issued into and uses a credential
# boundary that already exists rather than inventing a new one.
#
# An unset identity produces an unsigned binary on purpose. A build nobody can
# Gatekeeper-approve is honest about what it is; a build signed by a key sitting in shared
# CI is not.
set -eu

binary="${1:?usage: sign-macos.sh <binary>}"

if [ -z "${APPLE_SIGNING_IDENTITY:-}" ]; then
    echo "sign-macos: APPLE_SIGNING_IDENTITY unset, leaving ${binary} unsigned"
    exit 0
fi

# --options runtime is required for notarization; --timestamp binds a trusted timestamp so
# the signature keeps verifying after the certificate expires.
codesign --force --sign "${APPLE_SIGNING_IDENTITY}" --options runtime --timestamp "${binary}"
codesign --verify --strict --verbose=2 "${binary}"

echo "sign-macos: signed ${binary}"
