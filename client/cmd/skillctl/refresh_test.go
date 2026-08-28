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

	added, err := refreshSubscription(&subscription, defaultTrustedKeys(), time.Now().UTC())
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
	again, err := refreshSubscription(&subscription, defaultTrustedKeys(), time.Now().UTC())
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
	if _, err := refreshSubscription(&subscription, defaultTrustedKeys(), time.Now().UTC()); err == nil {
		t.Fatal("an announcement from a key this subscription never pinned must be refused")
	}
	if len(subscription.Parties) != 0 {
		t.Fatal("a refused announcement must not touch the subscription")
	}
}

// The replay the monotonic floor exists to stop: an operator retires a compromised key,
// and the announcement that first introduced it — still valid under the surviving key —
// is served again. Add-only merging would silently re-pin what was deliberately removed.
func TestRefreshRefusesAnAnnouncementItAlreadyActedOn(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	oldPub, oldKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "notary", oldPub); err != nil {
		t.Fatal(err)
	}

	// One fixed announcement, served over and over: the replayed document.
	issued := time.Now().UTC().Add(-time.Minute)
	envelope, err := attest.SignKeySet([]ed25519.PrivateKey{oldKey, newKey}, issued)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	subscription := Subscription{
		Name:       "acme",
		CatalogURL: server.URL + "/v1/catalogs/acme/plugins",
		KeyIDs:     []string{attest.KeyID(oldPub)},
	}
	if _, err := refreshSubscription(&subscription, defaultTrustedKeys(), time.Now().UTC()); err != nil {
		t.Fatalf("the first sight of an announcement must be accepted: %v", err)
	}
	if !subscription.KeysSeen.Equal(issued) {
		t.Fatalf("the floor must record the announcement acted on, got %s", subscription.KeysSeen)
	}
	if _, err := refreshSubscription(&subscription, defaultTrustedKeys(), time.Now().UTC()); err == nil {
		t.Fatal("the same announcement served again must be refused, not merged again")
	}
	_ = newPub
}

// Re-subscribing is how people change a URL or add a key. Before parties were carried
// over, it silently split a rotation pair back into two signers — handing a mid-rotation
// notary the two votes a threshold of two exists to demand of two different people.
func TestResubscribingKeepsPartiesAndTheReplayFloor(t *testing.T) {
	previous := map[string][]string{"notary": {"old", "new"}}
	merged := mergeParties(previous, nil, []string{"publisher", "old", "new"})
	if len(merged["notary"]) != 2 {
		t.Fatalf("the rotation pair must survive a re-subscribe, got %v", merged)
	}

	// A key no longer pinned drops out rather than lingering as a phantom member.
	pruned := mergeParties(previous, nil, []string{"publisher", "old"})
	if len(pruned["notary"]) != 1 || pruned["notary"][0] != "old" {
		t.Fatalf("an unpinned key must not stay in a party, got %v", pruned)
	}

	// A subscription with nothing grouped stays nil rather than growing an empty map.
	if mergeParties(nil, nil, []string{"publisher"}) != nil {
		t.Fatal("no parties in, no parties out")
	}
}
