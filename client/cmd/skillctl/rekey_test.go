package main

import "testing"

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
	keys := publisherKeys(subscription)
	if len(keys) != 1 || keys[0] != "publisher" {
		t.Fatalf("publisherKeys = %v, want only the publisher", keys)
	}
	// A notary mid-rotation replaces every notary key it had; the publisher is untouched,
	// and treating that as a re-key would drop the rollback guard for no reason.
	rotated := Subscription{
		KeyIDs:  []string{"publisher", "notary-newer"},
		Parties: map[string][]string{notaryParty: {"notary-newer"}},
	}
	if reKey(publisherKeys(subscription), publisherKeys(rotated)) {
		t.Fatal("a notary rotation was read as the publisher starting over")
	}
}
