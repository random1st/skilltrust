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
		set, signers, err := VerifyKeySet(envelope, pinned)
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
	if _, _, err := VerifyKeySet(envelope, NewTrustedKeys(pinnedPub)); !errors.Is(err, ErrUntrustedKey) {
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

	if _, _, err := VerifyKeySet(envelope, NewTrustedKeys(trustedPub)); err == nil {
		t.Fatal("a key set claiming someone else's id for foreign key bytes must be refused")
	}
}
