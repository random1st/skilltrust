package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/marketplace"
)

// The default install reports to nowhere, so the spool is the whole record — and it was
// being deleted the instant it was written.
//
// Deliver returned nil when no destination was configured, recordEvents read that as
// "delivered" and removed the file. A machine with no reporting.json therefore wrote every
// event and immediately destroyed it: `skillctl fleet ~/.skilltrust/events` on that machine
// printed nothing, the notary never heard, and an adopted or restored plugin was invisible
// to the person and to their organisation both. Which is every machine, by default.
func TestEventsSurviveWhenNobodyIsConfiguredToHearThem(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}

	recordEvents([]marketplace.Result{
		{Marketplace: "acme", Plugin: "runbook", Version: "1.0.0",
			Outcome: marketplace.OutcomeRestored, Quarantine: "/tmp/x"},
		{Marketplace: "acme", Plugin: "handbook", Version: "2.0.0",
			Outcome: marketplace.OutcomeAdapted, Adapted: "our staging URL"},
	}, nil, time.Now().UTC())

	entries, err := os.ReadDir(filepath.Join(home, "events"))
	if err != nil {
		t.Fatalf("the events directory was never created: %v", err)
	}
	spooled := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			spooled++
		}
	}
	if spooled != 2 {
		t.Fatalf("%d events left in the spool, want 2 — a machine with no destinations "+
			"configured reported nowhere at all", spooled)
	}
}
