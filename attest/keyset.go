package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// KeySetPayloadType identifies a signed announcement of a signer's current keys. It is a
// distinct payload type so a key-set signature can never be replayed as an attestation or
// a catalog, and vice versa.
const KeySetPayloadType = "application/vnd.skilltrust.keyset.v1+json"

// Errors a caller distinguishes when an announcement is refused. A stale announcement is
// an operational fact — a cache, or a notary that has been down — while an unproven key is
// an attempt to hand out trust the announcer cannot back.
var (
	ErrStaleKeySet = errors.New("the key set is too old to act on")
	ErrUnprovenKey = errors.New("an announced key did not prove it holds its private half")
)

// KeySetKey is one key in the announcement: its id and the PEM anyone can pin.
type KeySetKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// KeySet is the signed claim "these are my signing keys right now". It is how a signer
// rotates: the next key is announced under a signature from a key the consumer already
// pins, so trust extends along a chain instead of starting over. The set carries every
// current key, not a delta — a reader who missed an intermediate announcement still ends
// up in the right state.
//
// What this deliberately cannot do: revoke trust in the announcing key itself. Whoever
// holds a current key can announce a successor, so a stolen key remains dangerous for as
// long as consumers pin it. That is an argument for short overlap windows, not for a more
// elaborate scheme — and even a stolen countersigning key publishes nothing alone, because
// a threshold counts parties and the publisher's is still missing.
type KeySet struct {
	Version  int         `json:"version"`
	Keys     []KeySetKey `json:"keys"`
	IssuedAt time.Time   `json:"issued_at"`
}

// MaxKeySetAge bounds how old an announcement a consumer will act on. The notary signs
// one per request, so a fresh fetch is seconds old; anything near this bound arrived from
// a cache or a replay. It is a backstop for the machine that has never refreshed before
// and therefore has no previous announcement to compare against.
const MaxKeySetAge = 24 * time.Hour

// SignKeySet announces the public halves of the given keys, signed by every one of them.
//
// Signing with all keys — not just the newest — does two things. It lets a consumer
// pinning any single current key verify the announcement; and it makes every announced
// key prove it holds its own private half, which is what stops an announcement from
// naming a key the announcer does not control. Verification enforces that.
func SignKeySet(keys []ed25519.PrivateKey, now time.Time) (*Envelope, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("a key set needs at least one key")
	}
	set := KeySet{Version: StatementVersion, IssuedAt: now.UTC()}
	for _, key := range keys {
		public := key.Public().(ed25519.PublicKey)
		pem, err := EncodePublicKey(public)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, KeySetKey{ID: KeyID(public), PublicKey: string(pem)})
	}
	payload, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, err
	}
	envelope := SignPayload(KeySetPayloadType, payload, keys[0])
	for _, key := range keys[1:] {
		if err := Countersign(envelope, key); err != nil {
			return nil, err
		}
	}
	return envelope, nil
}

// VerifyKeySet checks an announcement against the keys a consumer already pins and returns
// the announced set plus the trusted keys that signed it. At least one pinned key must have
// signed; the announced keys themselves prove nothing about the envelope, or any stranger
// could announce their way into being trusted. The signers matter to the caller because
// trust is per subscription, not per machine: a key pinned for one catalog must not rotate
// another catalog's pins.
//
// Three rules, each closing a way an announcement could hand out trust it should not:
//
//   - Every announced id is recomputed from the announced key bytes. An announcement that
//     labels key bytes with someone else's id would let one signer impersonate another in
//     every store that indexes by id.
//   - Every announced key must itself have signed the announcement, checked against the
//     bytes it announces. Without this, whoever holds one current key could announce any
//     public key at all — the victim's own publisher key, collapsing two parties into one
//     and making the threshold unsatisfiable, or a pile of strangers' keys.
//   - The announcement must be no older than MaxKeySetAge relative to now. Freshness is
//     the floor under the caller's own monotonicity check: a machine with no previous
//     announcement to compare against would otherwise act on a replayed one.
func VerifyKeySet(envelope *Envelope, trusted *TrustedKeys, now time.Time) (*KeySet, []string, error) {
	payload, signers, err := VerifyPayloadSigners(envelope, KeySetPayloadType, trusted)
	if err != nil {
		return nil, nil, err
	}
	var set KeySet
	if err := json.Unmarshal(payload, &set); err != nil {
		return nil, nil, fmt.Errorf("%w: key set is not readable: %v", ErrMalformedEnvelope, err)
	}
	if set.Version != StatementVersion {
		return nil, nil, fmt.Errorf("%w: key set version %d", ErrUnknownVersion, set.Version)
	}
	if len(set.Keys) == 0 {
		return nil, nil, fmt.Errorf("%w: key set announces no keys", ErrMalformedEnvelope)
	}
	if age := now.Sub(set.IssuedAt); age > MaxKeySetAge {
		return nil, nil, fmt.Errorf("%w: the key set was issued %s ago, older than %s",
			ErrStaleKeySet, age.Round(time.Second), MaxKeySetAge)
	}

	announcedSignatures := map[string]string{}
	for _, signature := range envelope.Signatures {
		announcedSignatures[signature.KeyID] = signature.Sig
	}
	signed := pae(envelope.PayloadType, payload)
	for _, announced := range set.Keys {
		public, err := ParsePublicKey([]byte(announced.PublicKey))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: announced key %s: %v",
				ErrMalformedEnvelope, Fingerprint(announced.ID), err)
		}
		if KeyID(public) != announced.ID {
			return nil, nil, fmt.Errorf("%w: announced id %s does not match its key bytes",
				ErrMalformedEnvelope, Fingerprint(announced.ID))
		}
		raw, present := announcedSignatures[announced.ID]
		if !present {
			return nil, nil, fmt.Errorf("%w: announced key %s did not sign the announcement",
				ErrUnprovenKey, Fingerprint(announced.ID))
		}
		signature, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || !ed25519.Verify(public, signed, signature) {
			return nil, nil, fmt.Errorf("%w: announced key %s does not hold the key it claims",
				ErrUnprovenKey, Fingerprint(announced.ID))
		}
	}
	return &set, signers, nil
}
