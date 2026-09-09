package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

// A re-key restarts the publisher's sequence, so the mark this machine kept from the old
// chain would refuse every index the new one offers. Resetting it is right exactly when
// nothing that signed before still signs — and wrong in every other case, because a
// subscribe run out of habit must not quietly re-open the replay window.
func TestOnlyACompleteChangeOfPublisherCountsAsAReKey(t *testing.T) {
	for _, one := range []struct {
		name          string
		before, after []string
		want          bool
	}{
		{name: "same key re-pinned", before: []string{"a"}, after: []string{"a"}},
		{name: "a second publisher added", before: []string{"a"}, after: []string{"a", "b"}},
		{name: "one of two dropped", before: []string{"a", "b"}, after: []string{"a"}},
		{name: "thrown away and started again", before: []string{"a"}, after: []string{"b"}, want: true},
		{name: "both replaced", before: []string{"a", "b"}, after: []string{"c", "d"}, want: true},
		// Absence is not evidence. A subscription that never named a publisher apart from
		// its notary tells us nothing about the chain, and guessing would reset a guard on
		// no information at all.
		{name: "none pinned before", before: nil, after: []string{"a"}},
		{name: "none pinned now", before: []string{"a"}, after: nil},
	} {
		t.Run(one.name, func(t *testing.T) {
			if got := reKey(one.before, one.after); got != one.want {
				t.Fatalf("reKey(%v, %v) = %v, want %v", one.before, one.after, got, one.want)
			}
		})
	}
}

// The notary is not the publisher. It countersigns whatever sequence it is handed and
// rotates on its own timetable, so its keys must not be read as the chain changing.
func TestTheNotarysKeysAreNotThePublishersChain(t *testing.T) {
	subscription := Subscription{
		KeyIDs:  []string{"publisher", "notary-old", "notary-new"},
		Parties: map[string][]string{notaryParty: {"notary-old", "notary-new"}},
	}
	notary := notaryIdentity(subscription)
	keys := publisherKeys(subscription, notary)
	if len(keys) != 1 || keys[0] != "publisher" {
		t.Fatalf("publisherKeys = %v, want only the publisher", keys)
	}
	// A notary mid-rotation replaces every notary key it had; the publisher is untouched,
	// and treating that as a re-key would drop the rollback guard for no reason.
	rotated := Subscription{
		KeyIDs:  []string{"publisher", "notary-newer"},
		Parties: map[string][]string{notaryParty: {"notary-newer"}},
	}
	pooled := notaryIdentity(subscription, rotated)
	if reKey(publisherKeys(subscription, pooled), publisherKeys(rotated, pooled)) {
		t.Fatal("a notary rotation was read as the publisher starting over")
	}
}

// The subscription that was actually on the machine where this bug was found: two keys in
// one flat list, written before notary keys were grouped, so nothing in that record says
// which of them is the notary. Read on its own it looks like two publisher keys, and the
// unchanged notary then reads as "a publisher key still signs" — so a genuine re-key would
// not be recognised and the machine would stay refusing the catalog forever.
func TestAReKeyIsSeenEvenWhenTheOlderRecordNeverNamedItsNotary(t *testing.T) {
	legacy := Subscription{KeyIDs: []string{"old-publisher", "notary"}}
	rekeyed := Subscription{
		KeyIDs:  []string{"new-publisher", "notary"},
		Parties: map[string][]string{notaryParty: {"notary"}},
	}
	notary := notaryIdentity(legacy, rekeyed)
	if !reKey(publisherKeys(legacy, notary), publisherKeys(rekeyed, notary)) {
		t.Fatal("a publisher re-key went unnoticed because an old record did not label its notary")
	}
	// And the protection still holds when the publisher did not change: an ungrouped
	// record must not become a way to clear the mark by re-subscribing.
	same := Subscription{
		KeyIDs:  []string{"old-publisher", "notary"},
		Parties: map[string][]string{notaryParty: {"notary"}},
	}
	notary = notaryIdentity(legacy, same)
	if reKey(publisherKeys(legacy, notary), publisherKeys(same, notary)) {
		t.Fatal("labelling the notary on an unchanged publisher cleared the rollback mark")
	}
}

// A subscription old enough to carry the singular KeyID must still be readable, or the
// machines most likely to be stuck are the ones this cannot help.
func TestTheLegacySingularKeyIsStillAPublisherKey(t *testing.T) {
	legacy := Subscription{KeyID: "old-publisher"}
	if keys := publisherKeys(legacy, nil); len(keys) != 1 || keys[0] != "old-publisher" {
		t.Fatalf("publisherKeys = %v, want the legacy singular key", keys)
	}
}

func signedIndex(t *testing.T, dir string, key ed25519.PrivateKey, snapshot catalog.Snapshot) string {
	t.Helper()
	envelope, err := catalog.Sign(snapshot, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := filepath.Join(dir, CatalogFileName)
	if err := envelope.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	return path
}

func aKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return private
}

func aSnapshot(sequence int64) catalog.Snapshot {
	now := time.Now().UTC()
	return catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: "example", Sequence: sequence,
		IssuedAt: now, ValidUntil: now.Add(time.Hour),
	}
}

// An index that exists but cannot be read is not the same as no index at all. Treating it
// as a first publish restarts the sequence at 1, and every subscriber that already accepted
// a higher one refuses the chain from then on — which is the outage this whole flag exists
// to prevent, reached through the recovery path itself.
func TestAnUnreadablePreviousIndexRefusesRatherThanRestarting(t *testing.T) {
	for _, one := range []struct {
		name    string
		payload string
	}{
		{name: "not base64", payload: "!!!! not base64 !!!!"},
		{name: "not json", payload: base64.StdEncoding.EncodeToString([]byte("{{{"))},
		{name: "no sequence", payload: base64.StdEncoding.EncodeToString([]byte(`{"version":1}`))},
		{name: "negative sequence", payload: base64.StdEncoding.EncodeToString([]byte(`{"version":1,"sequence":-4}`))},
	} {
		t.Run(one.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, CatalogFileName)
			body, err := json.Marshal(attest.Envelope{
				PayloadType: catalog.PayloadType, Payload: one.payload,
				Signatures: []attest.Signature{{KeyID: "somebody", Sig: "AAAA"}},
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			previous, err := previousSnapshot(path, aKey(t), true)
			if !errors.Is(err, ErrNoPreviousSequence) {
				t.Fatalf("previousSnapshot = (%v, %v), want ErrNoPreviousSequence", previous, err)
			}
			if previous != nil {
				t.Fatal("an unreadable index was reported as a usable previous index")
			}
		})
	}
}

// The ceiling is not a rollback protection anybody would notice failing: +1 wraps to a
// negative sequence, which every consumer reads as an enormous step backwards.
func TestASequenceAtTheCeilingIsRefusedRatherThanWrapped(t *testing.T) {
	key := aKey(t)
	path := signedIndex(t, t.TempDir(), key, aSnapshot(math.MaxInt64))
	if previous, err := previousSnapshot(path, key, false); err == nil {
		t.Fatalf("previousSnapshot = (%v, nil), want a refusal rather than a wrap", previous)
	}
}

// Whether a signature was actually bypassed is a fact about what happened, not about which
// flags were typed. Announcing a re-key that did not occur is the same class of error as
// staying silent about one that did.
func TestOnlyARealBypassCountsAsHavingRekeyed(t *testing.T) {
	key := aKey(t)
	path := signedIndex(t, t.TempDir(), key, aSnapshot(5))

	previous, err := previousSnapshot(path, key, true)
	if err != nil {
		t.Fatalf("previousSnapshot: %v", err)
	}
	if previous.Bypassed {
		t.Fatal("-rekey on an index this key verifies was reported as a re-key")
	}
	if previous.Sequence != 5 {
		t.Fatalf("sequence = %d, want the published 5", previous.Sequence)
	}

	// The same file, read with a key that did not sign it.
	stranger := aKey(t)
	if _, err := previousSnapshot(path, stranger, false); err == nil {
		t.Fatal("a signature this key cannot verify was replaced without -rekey")
	}
	bypassed, err := previousSnapshot(path, stranger, true)
	if err != nil {
		t.Fatalf("previousSnapshot with -rekey: %v", err)
	}
	if !bypassed.Bypassed {
		t.Fatal("a genuine re-key was not reported as one")
	}
	// Continuing the chain is the whole point: restarting is what bricks subscribers.
	if bypassed.Sequence != 5 {
		t.Fatalf("sequence = %d, want the previous 5 so the next one advances", bypassed.Sequence)
	}
}

// Revocations are deliberately not carried across a re-key — signing for a claim this key
// cannot verify would be making somebody else's statement. That is right, and it is also a
// kill-switch quietly disappearing, so it has to be counted and said out loud.
func TestRevocationsAreDroppedAcrossAReKeyAndCounted(t *testing.T) {
	author := aKey(t)
	snapshot := aSnapshot(3)
	snapshot.Revoked = []catalog.Entry{
		{Digest: "sha256:one", Reason: "bad"},
		{Digest: "sha256:two", Reason: "worse"},
	}
	path := signedIndex(t, t.TempDir(), author, snapshot)

	previous, err := previousSnapshot(path, aKey(t), true)
	if err != nil {
		t.Fatalf("previousSnapshot: %v", err)
	}
	if len(previous.Revoked) != 0 {
		t.Fatalf("carried %d revocations out of an envelope this key cannot verify", len(previous.Revoked))
	}
	if previous.Dropped != 2 {
		t.Fatalf("Dropped = %d, want 2 so the operator is told to re-assert them", previous.Dropped)
	}
}
