// Package release is what a running skillctl and the release pipeline agree on: how a
// release's checksums are signed, how the archive for a platform is named, and how
// versions compare. It lives outside the client so the signing tool and the updater
// cannot drift apart on the one thing that has to match exactly.
package release

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/random1st/skilltrust/attest"
)

// PayloadType names what the release signature covers: the checksums file as goreleaser
// wrote it, byte for byte.
const PayloadType = "application/vnd.skilltrust.release-checksums.v1+text"

// SignatureSuffix is appended to the checksums file name for its envelope.
const SignatureSuffix = ".dsse.json"

// SignChecksums wraps the checksums text in a DSSE envelope signed by the release key.
func SignChecksums(checksums []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unusable release key")
	}
	if _, err := ParseChecksums(checksums); err != nil {
		return nil, err
	}
	return json.Marshal(attest.SignPayload(PayloadType, checksums, key))
}

// VerifyChecksums opens an envelope against the trusted release keys and returns the
// checksums it carries. The checksums are taken from the envelope, never from a separate
// download: the only bytes worth trusting are the ones the signature covers.
func VerifyChecksums(envelope []byte, trusted *attest.TrustedKeys) (map[string]string, error) {
	var env attest.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("the release signature is unreadable")
	}
	payload, _, err := attest.VerifyPayload(&env, PayloadType, trusted)
	if err != nil {
		return nil, fmt.Errorf("the release signature does not verify against the release key: %w", err)
	}
	return ParseChecksums(payload)
}

// ParseChecksums reads goreleaser's "<sha256>  <file>" lines into file -> hex digest.
func ParseChecksums(text []byte) (map[string]string, error) {
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(text)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || len(fields[0]) != 64 {
			return nil, fmt.Errorf("checksums line is not <sha256>  <file>: %q", scanner.Text())
		}
		out[fields[1]] = strings.ToLower(fields[0])
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the checksums file is empty")
	}
	return out, nil
}

// ArchiveName is the archive goreleaser publishes for a platform, as configured in
// client/.goreleaser.yaml: darwin ships one universal zip, windows zips, linux tarballs.
func ArchiveName(version, goos, goarch string) (string, error) {
	switch goos {
	case "darwin":
		return fmt.Sprintf("skillctl_%s_darwin_universal.zip", version), nil
	case "linux":
		return fmt.Sprintf("skillctl_%s_linux_%s.tar.gz", version, goarch), nil
	case "windows":
		return fmt.Sprintf("skillctl_%s_windows_%s.zip", version, goarch), nil
	}
	return "", fmt.Errorf("no release archive is published for %s/%s", goos, goarch)
}

// ChecksumsName is the checksums file goreleaser publishes for a version.
func ChecksumsName(version string) string {
	return fmt.Sprintf("skillctl_%s_checksums.txt", version)
}

// Version is a released version: major.minor.patch, no prerelease. Development builds
// and module pseudo-versions are not versions in this sense and never update.
type Version struct{ Major, Minor, Patch int }

func ParseVersion(text string) (Version, bool) {
	text = strings.TrimPrefix(strings.TrimSpace(text), "v")
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var out [3]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || strconv.Itoa(n) != part {
			return Version{}, false
		}
		out[i] = n
	}
	return Version{out[0], out[1], out[2]}, true
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Newer reports whether v is strictly newer than other. An updater must never go
// backwards: a "latest" pointing at an older release is a rollback, not an update.
func (v Version) Newer(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}
