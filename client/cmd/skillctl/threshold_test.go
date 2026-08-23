package main

import "testing"

// A subscription written before thresholds existed pins one key in `key_id`. Reading only
// `key_ids` would silently unsubscribe every machine that already follows something — and
// silently, because it surfaces as "none of which this machine pinned" rather than as an
// upgrade problem.
func TestASubscriptionFromBeforeThresholdsStillWorks(t *testing.T) {
	old := Subscription{Name: "acme", KeyID: "sha256:author"}
	if keys := old.Keys(); len(keys) != 1 || keys[0] != "sha256:author" {
		t.Fatalf("keys = %v", keys)
	}
	if old.Required() != 1 {
		t.Fatalf("required = %d; an old subscription requires one signature", old.Required())
	}
	if err := old.Satisfied([]string{"sha256:author"}); err != nil {
		t.Fatalf("the pinned key must still satisfy it: %v", err)
	}
}

// The point of a threshold: one key is not enough, however valid its signature.
func TestOneSignerDoesNotSatisfyAThresholdOfTwo(t *testing.T) {
	subscription := Subscription{
		Name: "acme", KeyIDs: []string{"sha256:author", "sha256:reviewer"}, Threshold: 2,
	}

	if err := subscription.Satisfied([]string{"sha256:author"}); err == nil {
		t.Fatal("one signature must not satisfy a threshold of two")
	}
	if err := subscription.Satisfied([]string{"sha256:author", "sha256:reviewer"}); err != nil {
		t.Fatalf("both pinned keys must satisfy it: %v", err)
	}
}

// Signatures from keys this machine did not pin do not count towards anything, however many
// there are. Otherwise an attacker reaches a threshold by signing repeatedly with keys they
// generated.
func TestUnpinnedSignersDoNotCount(t *testing.T) {
	subscription := Subscription{
		Name: "acme", KeyIDs: []string{"sha256:author", "sha256:reviewer"}, Threshold: 2,
	}
	err := subscription.Satisfied([]string{
		"sha256:author", "sha256:stranger-1", "sha256:stranger-2",
	})
	if err == nil {
		t.Fatal("keys this machine never pinned must not make up the count")
	}
}

// A machine that pinned nothing must refuse rather than accept anything, which is the
// direction to be wrong in.
func TestNoPinnedKeysSatisfiesNothing(t *testing.T) {
	if err := (Subscription{Name: "acme"}).Satisfied([]string{"sha256:whoever"}); err == nil {
		t.Fatal("a subscription with no pinned key must accept no signature")
	}
}
