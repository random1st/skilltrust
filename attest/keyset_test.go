package attest

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The rotation chain of trust in one round trip: a consumer pinning only the outgoing key
// verifies an announcement that carries the incoming one.
func TestKeySetVerifiesWithEitherCurrentKey(t *testing.T) {
	oldPub, oldKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := SignKeySet([]ed25519.PrivateKey{oldKey, newKey}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	for name, pinned := range map[string]*TrustedKeys{
		"outgoing": NewTrustedKeys(oldPub),
		"incoming": NewTrustedKeys(newPub),
	} {
		set, signers, err := VerifyKeySet(envelope, pinned, time.Now())
		if err != nil {
			t.Fatalf("pinning only the %s key must verify the announcement: %v", name, err)
		}
		if len(set.Keys) != 2 {
			t.Fatalf("the announcement must carry both keys, got %d", len(set.Keys))
		}
		if len(signers) != 1 {
			t.Fatalf("exactly the pinned key should count as signer, got %v", signers)
		}
	}
}

func TestKeySetFromAStrangerIsRefused(t *testing.T) {
	_, strangerKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pinnedPub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := SignKeySet([]ed25519.PrivateKey{strangerKey}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyKeySet(envelope, NewTrustedKeys(pinnedPub), time.Now()); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("a stranger's announcement must not verify, got %v", err)
	}
}

// An announcement that labels key bytes with a different signer's id must be refused:
// stores index by id, and accepting the lie would let one signer answer for another.
func TestKeySetWithAMislabelledKeyIsRefused(t *testing.T) {
	trustedPub, trustedKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := EncodePublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}

	// Honestly signed envelope over a dishonest statement: other's key bytes under
	// trusted's id.
	set := KeySet{Version: StatementVersion, IssuedAt: time.Now().UTC(), Keys: []KeySetKey{
		{ID: KeyID(trustedPub), PublicKey: string(otherPEM)},
	}}
	payload, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	envelope := SignPayload(KeySetPayloadType, payload, trustedKey)

	if _, _, err := VerifyKeySet(envelope, NewTrustedKeys(trustedPub), time.Now()); err == nil {
		t.Fatal("a key set claiming someone else's id for foreign key bytes must be refused")
	}
}

// The rule that stops an announcement from handing out trust its signer cannot back:
// every announced key must have signed the announcement with the very bytes announced.
// Without it, whoever holds one current key could announce the victim's own publisher key
// — collapsing two parties into one and making the threshold unsatisfiable — or bloat the
// trust store with strangers' keys.
func TestKeySetRefusesAKeyThatDidNotSign(t *testing.T) {
	trustedPub, trustedKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	strangerPub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	trustedPEM, err := EncodePublicKey(trustedPub)
	if err != nil {
		t.Fatal(err)
	}
	strangerPEM, err := EncodePublicKey(strangerPub)
	if err != nil {
		t.Fatal(err)
	}

	// Honest signature over a statement that smuggles in a key its signer does not hold.
	set := KeySet{Version: StatementVersion, IssuedAt: time.Now().UTC(), Keys: []KeySetKey{
		{ID: KeyID(trustedPub), PublicKey: string(trustedPEM)},
		{ID: KeyID(strangerPub), PublicKey: string(strangerPEM)},
	}}
	payload, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	envelope := SignPayload(KeySetPayloadType, payload, trustedKey)

	_, _, err = VerifyKeySet(envelope, NewTrustedKeys(trustedPub), time.Now())
	if !errors.Is(err, ErrUnprovenKey) {
		t.Fatalf("a key that did not sign must be refused, got %v", err)
	}
}

// Announcements stay verifiable under whichever key survives a rotation, so a replayed one
// would re-pin a key the operator retired. The age bound is the floor under the caller's
// own monotonicity check, for the machine that has nothing yet to compare against.
func TestKeySetOlderThanTheMaxAgeIsRefused(t *testing.T) {
	pub, key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Add(-MaxKeySetAge - time.Hour)
	envelope, err := SignKeySet([]ed25519.PrivateKey{key}, issued)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyKeySet(envelope, NewTrustedKeys(pub), time.Now()); !errors.Is(err, ErrStaleKeySet) {
		t.Fatalf("a replayed announcement must be refused as stale, got %v", err)
	}
	// The same document, read when it was fresh, is fine — the rule is age, not content.
	if _, _, err := VerifyKeySet(envelope, NewTrustedKeys(pub), issued.Add(time.Minute)); err != nil {
		t.Fatalf("a fresh announcement must verify: %v", err)
	}
}
