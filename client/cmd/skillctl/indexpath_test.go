package main

import (
	"path/filepath"
	"testing"
)

// Where the verifier reads the index from is part of the trust story: a subscription with
// a notary must read what the notary served, and one without must read what the git
// checkout carries — never a mix decided by whichever file happens to exist.
func TestIndexPathFollowsTheSubscription(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	plain := Subscription{Name: "acme"}
	if got := indexPath(plain); got != filepath.Join(
		Home(), "sources", "acme", CatalogFileName) {
		t.Fatalf("a git subscription must read the checkout's index, got %s", got)
	}

	notarised := Subscription{Name: "acme", CatalogURL: "https://notary.example.com/acme"}
	if got := indexPath(notarised); got != filepath.Join(
		Home(), "indexes", "acme.dsse.json") {
		t.Fatalf("a notary subscription must read the fetched index, got %s", got)
	}
}
