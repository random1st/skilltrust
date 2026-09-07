package main

// releasePublicKeyPEM is the public half of the key that signs every release's
// checksums (tools/release-sign). `skillctl update` accepts a release only when its
// checksums verify against this key, so control of the download host alone cannot push
// a binary to anyone.
//
// The private half lives on the release machine, outside every repository, and is
// rotated by shipping a release signed by the old key whose binary embeds the new one.
// Fingerprint 7e56e71d7fc07ab6, generated 2026-09-07.
const releasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0Bbi7kCK5pNaa9XuMtxUAMrAYhXgAfcEYW+hDYixriQ=
-----END PUBLIC KEY-----
`
