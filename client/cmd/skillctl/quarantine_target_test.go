package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/internal/marketplace"
)

// Recovering A must never adopt B's edit just because B was quarantined later. Exercise
// both recovery orders, using the same plugin name, version and quarantine timestamp.
func TestReclaimQuarantineKeepsMarketplaceIdentity(t *testing.T) {
	for _, order := range [][]string{{"one", "two"}, {"two", "one"}} {
		t.Run(order[0]+"-first", func(t *testing.T) {
			fixture := newRecoveryFixture(t)
			home, source := fixture.home, fixture.source
			var results []marketplace.Result
			var subscriptions []Subscription
			for _, market := range []string{"one", "two"} {
				installed := marketplace.InstalledPath(home, market, "runbook", "1.0.0")
				writeQuarantineSkill(t, installed, "my "+market+" edit\n")
				if _, err := marketplace.Restore(installed, source, quarantineRoot(), "runbook",
					time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)); err != nil {
					t.Fatal(err)
				}
				results = append(results, marketplace.Result{
					Marketplace: market, Plugin: "runbook", Version: "1.0.0",
					Outcome: marketplace.OutcomeVerified, Signed: fixture.snapshot.Skills[0].Digest,
				})
				subscription := fixture.subscription
				subscription.Name = market
				subscriptions = append(subscriptions, subscription)
				snapshot := fixture.snapshot
				snapshot.Name = market
				writeCatalogIndex(t, subscription, snapshot, fixture.key)
			}
			if err := saveSubscriptions(subscriptions); err != nil {
				t.Fatal(err)
			}
			for _, market := range order {
				if code := reclaimFromQuarantine(results, home, market, "runbook"); code != exitClean {
					t.Fatalf("recovering %s: exit %d", market, code)
				}
				assertQuarantineSkill(t, marketplace.InstalledPath(home, market, "runbook", "1.0.0"),
					"my "+market+" edit\n")
			}
		})
	}
}

func TestReclaimQuarantineDoesNotGuessLegacyOrigin(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	home := t.TempDir()
	installed := marketplace.InstalledPath(home, "one", "runbook", "1.0.0")
	writeQuarantineSkill(t, installed, "published\n")
	legacy := filepath.Join(quarantineRoot(), "runbook-20260905T120000Z")
	writeQuarantineSkill(t, legacy, "another client's edit\n")
	results := []marketplace.Result{{
		Marketplace: "one", Plugin: "runbook", Version: "1.0.0", Outcome: marketplace.OutcomeVerified,
	}}
	if code := reclaimFromQuarantine(results, home, "one", "runbook"); code == exitClean {
		t.Fatal("legacy name has no installed target: selecting one current marketplace cannot prove its origin")
	}
	assertQuarantineSkill(t, installed, "published\n")
	assertQuarantineSkill(t, legacy, "another client's edit\n")
}

func writeQuarantineSkill(t *testing.T, directory, body string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertQuarantineSkill(t *testing.T, directory, want string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(directory, "SKILL.md"))
	if err != nil || string(body) != want {
		t.Fatalf("%s: skill = %q (%v), want %q", directory, body, err, want)
	}
}
