package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

// The hole party-counting closes: a machine pinning a notary's rotation pair at threshold
// two must not accept a catalog the two notary keys signed alone. Two keys, one owner —
// nobody second agreed to anything.
func TestARotationPairCountsOnceTowardTheThreshold(t *testing.T) {
	subscription := Subscription{
		Name:      "acme",
		KeyIDs:    []string{"publisher"},
		Threshold: 2,
		Parties:   map[string][]string{"notary": {"notary-old", "notary-new"}},
	}

	if err := subscription.Satisfied([]string{"notary-old", "notary-new"}); err == nil {
		t.Fatal("both halves of one notary's rotation pair must not satisfy threshold 2")
	}
	if err := subscription.Satisfied([]string{"publisher", "notary-old"}); err != nil {
		t.Fatalf("publisher plus the outgoing key is two parties: %v", err)
	}
	if err := subscription.Satisfied([]string{"publisher", "notary-new"}); err != nil {
		t.Fatalf("publisher plus the incoming key is two parties: %v", err)
	}
	if err := subscription.Satisfied([]string{"publisher", "notary-old", "notary-new"}); err != nil {
		t.Fatalf("all three signatures are still two parties, which meets 2: %v", err)
	}
}

// A subscription with no parties behaves exactly as before this field existed. Fleets in
// the field have flat pins; changing what their files mean would be a silent trust change.
func TestFlatSubscriptionsCountKeysAsBefore(t *testing.T) {
	subscription := Subscription{
		Name:      "acme",
		KeyIDs:    []string{"a", "b"},
		Threshold: 2,
	}
	if err := subscription.Satisfied([]string{"a", "b"}); err != nil {
		t.Fatalf("two distinct flat keys meet threshold 2: %v", err)
	}
	if err := subscription.Satisfied([]string{"a"}); err == nil {
		t.Fatal("one key must not meet threshold 2")
	}
}

// The consumer half of a rotation, end to end: the notary announces old+new signed by
// both, the machine pins old — refresh pins new into old's party, and the subscription
// then accepts publisher+new while still refusing old+new alone.
func TestRefreshPinsTheAnnouncedKeyIntoTheSameParty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	publisherPub, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPub, oldKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", publisherPub); err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "notary", oldPub); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/keys" {
			http.NotFound(w, r)
			return
		}
		envelope, err := attest.SignKeySet([]ed25519.PrivateKey{oldKey, newKey}, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	subscription := Subscription{
		Name:       "acme",
		CatalogURL: server.URL + "/v1/catalogs/acme/plugins",
		KeyIDs:     []string{attest.KeyID(publisherPub), attest.KeyID(oldPub)},
		Threshold:  2,
	}

	added, err := refreshSubscription(&subscription, defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != attest.KeyID(newPub) {
		t.Fatalf("refresh should add exactly the incoming key, got %v", added)
	}

	if err := subscription.Satisfied([]string{attest.KeyID(publisherPub), attest.KeyID(newPub)}); err != nil {
		t.Fatalf("after refresh, publisher plus the incoming key must verify: %v", err)
	}
	if err := subscription.Satisfied([]string{attest.KeyID(oldPub), attest.KeyID(newPub)}); err == nil {
		t.Fatal("after refresh, the rotation pair alone must still not reach threshold 2")
	}

	// The incoming key's bytes landed in the machine store, so verification — which
	// resolves ids through that store — can actually use it.
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, known := trusted.Lookup(attest.KeyID(newPub)); !known {
		t.Fatal("the incoming key must be pinned in the trust store")
	}

	// Refreshing again changes nothing: the announcement is already reflected.
	again, err := refreshSubscription(&subscription, defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("a second refresh must be a no-op, got %v", again)
	}
}

// An announcement signed only by keys this subscription never pinned extends nothing,
// even when the machine's trust store knows those keys from another catalog. Trust is
// per subscription; one notary must not rotate another notary's pins.
func TestRefreshRefusesAnAnnouncementFromAForeignNotary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	minePub, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "mine", minePub); err != nil {
		t.Fatal(err)
	}
	// The foreign notary is trusted on this machine — for some other subscription.
	if err := attest.PinKey(defaultTrustedKeys(), "other", otherPub); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelope, err := attest.SignKeySet([]ed25519.PrivateKey{otherKey}, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	subscription := Subscription{
		Name:       "acme",
		CatalogURL: server.URL + "/v1/catalogs/acme/plugins",
		KeyIDs:     []string{attest.KeyID(minePub)},
	}
	if _, err := refreshSubscription(&subscription, defaultTrustedKeys()); err == nil {
		t.Fatal("an announcement from a key this subscription never pinned must be refused")
	}
	if len(subscription.Parties) != 0 {
		t.Fatal("a refused announcement must not touch the subscription")
	}
}
