// Package attest signs and verifies statements about a skill's canonical digest.
//
// The envelope is DSSE: the signature covers the exact payload bytes, which are carried
// base64-encoded rather than re-serialized on the verifying side. That is not ceremony.
// Today this repository found two implementations of a canonical tar format that
// disagreed on trailing padding and two header fields, producing different digests for
// identical trees. Re-serializing a JSON statement before checking its signature invites
// the same class of failure — key order, number formatting, escaping — and it would
// surface as an unexplainable signature mismatch rather than as a diff. Signing bytes and
// verifying those same bytes removes the question entirely.
//
// Signing is Ed25519 with a locally held key. Keyless Sigstore belongs behind the same
// interface later, as the low-friction community path; the offline, bring-your-own-root
// case is the one that cannot be served by anything else, so it is built first.
package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PayloadType identifies what the signature covers. It is part of the signed
// pre-authentication encoding, so a signature over an attestation can never be replayed as
// a signature over a different kind of document.
const PayloadType = "application/vnd.skilltrust.attestation.v1+json"

// StatementVersion is the payload schema version.
const StatementVersion = 1

// Subject is what the statement is about: a named skill, identified by digest.
type Subject struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// Source optionally records where the reviewed bytes came from.
type Source struct {
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
}

// Statement is the signed claim. It deliberately says who approved the bytes and when,
// because that is the question an audit asks and a digest alone cannot answer.
type Statement struct {
	Version    int       `json:"version"`
	Subject    Subject   `json:"subject"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
	Source     *Source   `json:"source,omitempty"`
	Notes      string    `json:"notes,omitempty"`
}

// Signature is one signer's assertion over the payload.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Envelope is a DSSE envelope carrying the statement and its signatures.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Errors callers distinguish. An unverifiable envelope and an invalid one are different
// facts, exactly as a missing lock and a corrupt lock are.
var (
	ErrNoSignatures      = errors.New("envelope carries no signatures")
	ErrUntrustedKey      = errors.New("no signature from a trusted key")
	ErrBadSignature      = errors.New("signature does not verify")
	ErrDigestMismatch    = errors.New("statement subject does not match the tree on disk")
	ErrWrongPayload      = errors.New("envelope payload type is not an attestation")
	ErrUnknownVersion    = errors.New("statement version is not understood by this build")
	ErrMalformedEnvelope = errors.New("envelope is not readable")
)

// pae builds the DSSE pre-authentication encoding. Binding the payload type into the
// signed bytes is what stops a signature being lifted onto a different document type.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payload))
}

// SignPayload signs exact bytes under a payload type and returns a DSSE envelope.
//
// The payload type is bound into the signed bytes, so a signature made for one kind of
// document cannot be presented as a signature over another. Callers pass the bytes they
// mean to sign; nothing is re-serialized on the way in or out.
func SignPayload(payloadType string, payload []byte, key ed25519.PrivateKey) *Envelope {
	signature := ed25519.Sign(key, pae(payloadType, payload))
	return &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: KeyID(key.Public().(ed25519.PublicKey)),
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	}
}

// VerifyPayload checks an envelope of the expected type against the pinned keys and
// returns the exact bytes that were signed, plus the key that signed them.
func VerifyPayload(envelope *Envelope, expectedType string, trusted *TrustedKeys) ([]byte, string, error) {
	if envelope.PayloadType != expectedType {
		return nil, "", fmt.Errorf("%w: %q", ErrWrongPayload, envelope.PayloadType)
	}
	if len(envelope.Signatures) == 0 {
		return nil, "", ErrNoSignatures
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("%w: payload is not base64: %v", ErrMalformedEnvelope, err)
	}

	signed := pae(envelope.PayloadType, payload)
	sawTrustedKey := false
	for _, signature := range envelope.Signatures {
		public, known := trusted.Lookup(signature.KeyID)
		if !known {
			continue
		}
		sawTrustedKey = true

		raw, err := base64.StdEncoding.DecodeString(signature.Sig)
		if err != nil {
			continue
		}
		if !ed25519.Verify(public, signed, raw) {
			return nil, "", fmt.Errorf("%w for key %s", ErrBadSignature, signature.KeyID)
		}
		return payload, signature.KeyID, nil
	}

	if !sawTrustedKey {
		return nil, "", ErrUntrustedKey
	}
	return nil, "", ErrBadSignature
}

// Sign marshals the statement, signs those exact bytes, and returns the envelope.
func Sign(statement Statement, key ed25519.PrivateKey) (*Envelope, *Statement, error) {
	statement.Version = StatementVersion
	if statement.Subject.Name == "" || statement.Subject.Digest == "" {
		return nil, nil, errors.New("a statement needs a subject name and digest")
	}
	if statement.ApprovedBy == "" {
		return nil, nil, errors.New("a statement needs an approver; an unattributed " +
			"approval cannot answer the question an audit asks")
	}
	if statement.ApprovedAt.IsZero() {
		return nil, nil, errors.New("a statement needs an approval time")
	}
	statement.ApprovedAt = statement.ApprovedAt.UTC().Truncate(time.Second)

	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, nil, err
	}

	return SignPayload(PayloadType, payload, key), &statement, nil
}

// Verify checks the envelope against the trusted keys and returns the statement it
// asserts. It never returns a statement it could not verify: an unverified claim being
// handed back for inspection is how one ends up acting on it.
func Verify(envelope *Envelope, trusted *TrustedKeys) (*Statement, string, error) {
	payload, keyID, err := VerifyPayload(envelope, PayloadType, trusted)
	if err != nil {
		return nil, "", err
	}

	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, "", fmt.Errorf("%w: payload is not a statement: %v", ErrMalformedEnvelope, err)
	}
	if statement.Version != StatementVersion {
		return nil, "", fmt.Errorf("%w: version %d", ErrUnknownVersion, statement.Version)
	}
	return &statement, keyID, nil
}

// KeyID is a stable identifier for a public key: the digest of its PKIX encoding.
func KeyID(public ed25519.PublicKey) string {
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		// Ed25519 keys always marshal; a failure here means memory corruption.
		panic("attest: cannot marshal an ed25519 public key: " + err.Error())
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// GenerateKey returns a fresh signing key.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// WritePrivateKey stores the key readable only by its owner. A signing key with loose
// permissions is a signing key anything running as that user can borrow.
func WritePrivateKey(path string, key ed25519.PrivateKey) error {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	return writeFile(path, block, 0o600)
}

// WritePublicKey stores the verifying half, which is safe to publish.
func WritePublicKey(path string, key ed25519.PublicKey) error {
	block, err := encodePublicKey(key)
	if err != nil {
		return err
	}
	return writeFile(path, block, 0o644)
}

// encodePublicKey renders a key as PEM, the one form this project stores keys in.
func encodePublicKey(key ed25519.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), nil
}

// LoadPrivateKey reads a signing key and refuses one the whole machine can read.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := assertOwnerOnly(path, info); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a usable private key: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T; only ed25519 is supported", path, parsed)
	}
	return key, nil
}

// LoadPublicKey reads a verifying key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(raw)
}

// ParsePublicKey decodes a PEM-encoded verifying key.
func ParsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is a %T; only ed25519 is supported", parsed)
	}
	return key, nil
}

// TrustedKeys is the pinned root set: the keys whose approvals this deployment accepts.
type TrustedKeys struct {
	keys map[string]ed25519.PublicKey
}

// trustedKeysFile is the on-disk form, a mapping from a human label to a PEM key.
type trustedKeysFile struct {
	Version int               `json:"version"`
	Keys    map[string]string `json:"keys"`
}

// NewTrustedKeys builds a set from already-parsed keys.
func NewTrustedKeys(keys ...ed25519.PublicKey) *TrustedKeys {
	set := &TrustedKeys{keys: map[string]ed25519.PublicKey{}}
	for _, key := range keys {
		set.keys[KeyID(key)] = key
	}
	return set
}

// Lookup resolves a key id to its public key.
func (t *TrustedKeys) Lookup(keyID string) (ed25519.PublicKey, bool) {
	key, ok := t.keys[keyID]
	return key, ok
}

// Len reports how many keys are pinned.
func (t *TrustedKeys) Len() int { return len(t.keys) }

// LoadTrustedKeys reads the pinned set. An empty set is an error rather than a silently
// permissive default: a verifier that trusts nothing should say so, not accept everything.
func LoadTrustedKeys(path string) (*TrustedKeys, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var document trustedKeysFile
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%s is not a readable trusted-key file: %w", path, err)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("%s uses trusted-key format version %d, this build understands 1",
			path, document.Version)
	}
	if len(document.Keys) == 0 {
		return nil, fmt.Errorf("%s pins no keys; a verifier with an empty root set can "+
			"approve nothing and must not be mistaken for one that approves everything", path)
	}

	set := &TrustedKeys{keys: map[string]ed25519.PublicKey{}}
	for label, encoded := range document.Keys {
		key, err := ParsePublicKey([]byte(encoded))
		if err != nil {
			return nil, fmt.Errorf("trusted key %q in %s: %w", label, path, err)
		}
		set.keys[KeyID(key)] = key
	}
	return set, nil
}

// SaveTrustedKeys writes a pinned set keyed by label.
func SaveTrustedKeys(path string, labelled map[string]ed25519.PublicKey) error {
	document := trustedKeysFile{Version: 1, Keys: map[string]string{}}
	for label, key := range labelled {
		encoded, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}
		document.Keys[label] = string(pem.EncodeToMemory(
			&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(body, '\n'), 0o644)
}

// LoadEnvelope reads a DSSE envelope from disk.
func LoadEnvelope(path string) (*Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedEnvelope, path, err)
	}
	return &envelope, nil
}

// Save writes the envelope atomically, so an interrupted write cannot leave a truncated
// attestation that later reads as merely unparseable rather than as absent.
func (e *Envelope) Save(path string) error {
	body, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(body, '\n'), 0o644)
}

// DefaultName is the conventional attestation filename beside a skill directory.
func DefaultName(directory string) string {
	return filepath.Clean(directory) + ".att.json"
}

func writeFile(path string, body []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Fingerprint shortens a key id for display without ever being used for comparison.
func Fingerprint(keyID string) string {
	trimmed := strings.TrimPrefix(keyID, "sha256:")
	if len(trimmed) > 16 {
		return trimmed[:16]
	}
	return trimmed
}

// PinKey adds one key to the pinned set under a label, preserving every key already there.
//
// It merges at the file level rather than through TrustedKeys because loading re-keys the
// set by key ID and discards the labels. Round-tripping through that would silently rename
// every previously pinned publisher to a hex string the first time a second one was added —
// the kind of loss that is invisible until somebody has to work out whose key is whose.
func PinKey(path, label string, public ed25519.PublicKey) error {
	document := trustedKeysFile{Version: 1, Keys: map[string]string{}}
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &document); err != nil {
			return fmt.Errorf("%s is not a readable trusted-key file: %w", path, err)
		}
		if document.Version != 1 {
			return fmt.Errorf("%s uses trusted-key format version %d, this build understands 1",
				path, document.Version)
		}
		if document.Keys == nil {
			document.Keys = map[string]string{}
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	encoded, err := encodePublicKey(public)
	if err != nil {
		return err
	}
	// A label already in use must not be repointed silently: that is how a publisher key is
	// replaced by an attacker's under a name everyone still trusts.
	if existing, taken := document.Keys[label]; taken && existing != string(encoded) {
		return fmt.Errorf("%q already pins a different key in %s; remove it deliberately "+
			"before pinning another", label, path)
	}
	document.Keys[label] = string(encoded)

	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(body, '\n'), 0o644)
}
