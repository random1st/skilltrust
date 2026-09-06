package main

import (
	"context"
	"crypto/ed25519"
	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/source"
	"testing"
	"time"
)

func TestReviewPublicSubscriptionPreservesConcurrentTrustAndSequence(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
		t.Fatal(err)
	}
	subscriptions, err := loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	notaryID := attest.KeyID(f.notaries[0].Public().(ed25519.PublicKey))
	fetch := f.r.fetch
	f.r.fetch = func(ctx context.Context, root, name, repository, ref string) (source.Source, error) {
		fetched, err := fetch(ctx, root, name, repository, ref)
		if err != nil {
			return fetched, err
		}
		// A hook/doctor accepts a newer catalog while this command waits on Git.
		state, err := catalog.LoadState(snapshotStatePath(subscriptions[0]))
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Save(snapshotStatePath(subscriptions[0]), f.snapshot.Sequence+1, f.now); err != nil {
			t.Fatal(err)
		}
		// The operator explicitly retires the old notary pin in the same interval.
		pins, err := attest.PinnedKeys(defaultTrustedKeys())
		if err != nil {
			t.Fatal(err)
		}
		for label, key := range pins {
			if attest.KeyID(key) == notaryID {
				if err := attest.UnpinKey(defaultTrustedKeys(), label); err != nil {
					t.Fatal(err)
				}
			}
		}
		return fetched, nil
	}
	_, _, subscribeErr := f.r.subscribe(context.Background(), "axela://team/acme")
	state, err := catalog.LoadState(snapshotStatePath(subscriptions[0]))
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != f.snapshot.Sequence+1 {
		t.Errorf("newer accepted sequence was rolled back: got %d, want %d (subscribe error: %v)", state.Sequence, f.snapshot.Sequence+1, subscribeErr)
	}
	pins, err := attest.PinnedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range pins {
		if attest.KeyID(key) == notaryID {
			t.Errorf("explicitly retired notary was silently re-pinned (subscribe error: %v)", subscribeErr)
		}
	}
}

func TestReviewPublicSubscriptionKeepsRotationWithinTargetPins(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
		t.Fatal(err)
	}
	subscriptions, err := loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherID := attest.KeyID(otherPublic)
	if err := attest.PinKey(defaultTrustedKeys(), "notary:other", otherPublic); err != nil {
		t.Fatal(err)
	}
	subscriptions = append(subscriptions, Subscription{
		Name: "other", Repository: "https://github.com/other/skills.git", Ref: "refs/heads/main",
		CatalogURL: "https://axela.app/v1/catalogs/other/other",
		KeyIDs:     []string{otherID}, Parties: map[string][]string{notaryParty: {otherID}},
	})
	if err := saveSubscriptions(subscriptions); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	f.keyTime = f.now
	f.notaries = []ed25519.PrivateKey{otherPrivate}
	f.signKeySet()
	f.signCatalog(f.publisher, otherPrivate)
	f.signDescriptor(otherPrivate)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
		t.Error("catalog acme accepted a notary signed only by the unrelated other catalog pin")
	}
	after, err := loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range after {
		if sub.Name == "acme" && containsPublicKeyID(sub.Parties[notaryParty], otherID) {
			t.Error("catalog acme now trusts other catalog notary without proof from its established notary")
		}
	}
}
