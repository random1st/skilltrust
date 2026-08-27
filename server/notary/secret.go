package notary

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// Secret is a bearer token the notary can check but not reproduce.
//
// Only the digest is kept, for one reason that matters more as deployments grow: a
// hosted notary stores organisations in a database, and a database that holds tokens in
// the clear turns any read - a backup, a query, an over-broad IAM policy - into every
// organisation's publish credential. Keeping the digest means a leak of the store is not
// a leak of the tokens.
//
// The zero Secret is a disabled role: an organisation that configures no ingest token
// has the ingest endpoint closed, and no presented value opens it — including the empty
// string, which is what an absent Authorization header reduces to.
type Secret struct {
	digest  [sha256.Size]byte
	enabled bool
}

// NewSecret takes the plaintext an operator wrote in a config file. Empty means the role
// is disabled rather than open.
func NewSecret(plaintext string) Secret {
	if plaintext == "" {
		return Secret{}
	}
	return Secret{digest: sha256.Sum256([]byte(plaintext)), enabled: true}
}

// SecretFromDigest reconstructs a Secret from stored hex, for a directory that persists
// digests rather than plaintext.
func SecretFromDigest(encoded string) (Secret, error) {
	if encoded == "" {
		return Secret{}, nil
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return Secret{}, err
	}
	if len(raw) != sha256.Size {
		return Secret{}, errors.New("a token digest must be sha256")
	}
	secret := Secret{enabled: true}
	copy(secret.digest[:], raw)
	return secret, nil
}

// Digest is the hex form to store. Empty for a disabled role.
func (s Secret) Digest() string {
	if !s.enabled {
		return ""
	}
	return hex.EncodeToString(s.digest[:])
}

// Enabled reports whether any value can match.
func (s Secret) Enabled() bool { return s.enabled }

// Matches compares in constant time. The hash and the comparison run even for a disabled
// secret, so a closed role and a wrong token take the same time — the response must not
// say which of the two it was.
func (s Secret) Matches(presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	equal := subtle.ConstantTimeCompare(s.digest[:], sum[:])
	return equal == 1 && s.enabled
}
