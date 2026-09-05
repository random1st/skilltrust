package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
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

func TestConcurrentCurrentChecksAdvanceTheSequenceAndCoalesce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	public, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	now := time.Now().UTC().Truncate(time.Second)
	for _, checked := range []int{1, 2} {
		wait.Add(1)
		go func(checked int) {
			defer wait.Done()
			<-start
			_, err := recordCurrentChecks(0, CurrentCheck{
				Scope:      CheckScopeManaged,
				CheckedAt:  now,
				FreshUntil: now.Add(time.Hour),
				Complete:   true,
				Checked:    checked,
			})
			errs <- err
		}(checked)
	}
	close(start)
	wait.Wait()
	close(errs)

	for err := range errs {
		if err != nil && !errors.Is(err, report.ErrNoDestinations) {
			t.Fatalf("recordCurrentChecks = %v", err)
		}
	}

	pending, err := spool().Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1 coalesced check", len(pending))
	}
	if filepath.Base(pending[0]) != "check-managed.json" {
		t.Fatalf("pending file = %q", filepath.Base(pending[0]))
	}

	envelope, err := attest.LoadEnvelope(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	check, _, err := report.VerifyCheck(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if check.Sequence != 2 {
		t.Fatalf("sequence = %d, want 2 after two concurrent writes", check.Sequence)
	}

	state, err := catalog.LoadState(checkSequencePath(CheckScopeManaged))
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 2 {
		t.Fatalf("saved sequence = %d, want 2", state.Sequence)
	}
}

func TestEventsQueueBeforeAContendedReportingLock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homePath("reporting.lock"), []byte("busy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := recordReports([]report.Event{{
		Kind:        report.KindRestored,
		At:          time.Now().UTC(),
		Marketplace: "acme",
		Plugin:      "runbook",
	}}, nil, 50*time.Millisecond)
	if !errors.Is(err, errReportingBusy) {
		t.Fatalf("recordReports error = %v, want reporting busy", err)
	}
	if status.QueuedEvents != 1 {
		t.Fatalf("queued events = %d, want 1", status.QueuedEvents)
	}

	pending, err := spool().Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want the event preserved in the spool", len(pending))
	}
}

func TestFlushPendingReportsHonorsOneAbsoluteDeadline(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	recordEvents([]marketplace.Result{
		{Marketplace: "acme", Plugin: "one", Version: "1.0.0", Outcome: marketplace.OutcomeRestored},
		{Marketplace: "acme", Plugin: "two", Version: "1.0.0", Outcome: marketplace.OutcomeRestored},
		{Marketplace: "acme", Plugin: "three", Version: "1.0.0", Outcome: marketplace.OutcomeRestored},
	}, nil, now)

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
	}))
	defer server.Close()

	if err := os.WriteFile(reportConfigPath(), []byte(`{
  "destinations": [{"kind":"webhook","url":"`+server.URL+`"}]
}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	status, err := FlushPendingEventReports(80 * time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FlushPendingEventReports error = %v, want deadline exceeded", err)
	}
	if status.DeliveredEvents != 0 {
		t.Fatalf("delivered events = %d, want 0", status.DeliveredEvents)
	}
	if status.PendingEvents != 3 {
		t.Fatalf("pending events = %d, want all 3 retained", status.PendingEvents)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("webhook requests = %d, want 1 before the shared deadline stops retries", got)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("flush took %s, want one shared budget for all pending events", elapsed)
	}

	pending, err := spool().Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 3 {
		t.Fatalf("pending files = %d, want all 3 immutable events retained", len(pending))
	}
}

func TestRecordCurrentChecksReturnsDigestAfterDelivery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}

	sink := filepath.Join(home, "delivered")
	if err := os.WriteFile(reportConfigPath(), []byte(`{
  "destinations": [{
    "kind":"file",
    "directory":"`+sink+`",
    "payloads":["checks"],
    "healthy_checks":true
  }]
}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	status, err := recordCurrentChecks(2*time.Second, CurrentCheck{
		Scope:      CheckScopeManaged,
		CheckedAt:  now,
		FreshUntil: now.Add(time.Hour),
		Complete:   true,
		Checked:    1,
	})
	if err != nil {
		t.Fatalf("recordCurrentChecks = %v", err)
	}
	if status.DeliveredChecks != 1 {
		t.Fatalf("delivered checks = %d, want 1", status.DeliveredChecks)
	}
	got := status.CheckDigests[CheckScopeManaged]
	if got == "" {
		t.Fatalf("check digest for %q missing", CheckScopeManaged)
	}

	delivered, err := os.ReadDir(sink)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 1 {
		t.Fatalf("delivered files = %d, want 1", len(delivered))
	}
	body, err := os.ReadFile(filepath.Join(sink, delivered[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("check digest = %s, want %s", got, want)
	}

	pending, err := spool().Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending files = %d, want delivered check removed from spool", len(pending))
	}
}

func TestManagedCurrentCheckClampsFreshnessToCatalogMinimumAndCheckAge(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	t.Run("earliest catalog wins", func(t *testing.T) {
		check := managedCurrentCheck(ManagedCheck{
			Scope:     CheckScopeManaged,
			Complete:  true,
			CheckedAt: now,
			Catalogs: []ManagedCatalogCheck{
				{Name: "acme", Sequence: 1, ValidUntil: now.Add(20 * time.Hour)},
				{Name: "beta", Sequence: 1, ValidUntil: now.Add(10 * time.Hour)},
			},
			Results: []marketplace.Result{{Outcome: marketplace.OutcomeVerified}},
		})
		want := now.Add(10 * time.Hour)
		if !check.FreshUntil.Equal(want) {
			t.Fatalf("fresh until = %s, want earliest catalog expiry %s", check.FreshUntil, want)
		}
	})

	t.Run("check age clamps long catalog validity", func(t *testing.T) {
		check := managedCurrentCheck(ManagedCheck{
			Scope:     CheckScopeManaged,
			Complete:  true,
			CheckedAt: now,
			Catalogs: []ManagedCatalogCheck{
				{Name: "acme", Sequence: 1, ValidUntil: now.Add(48 * time.Hour)},
			},
			Results: []marketplace.Result{{Outcome: marketplace.OutcomeVerified}},
		})
		want := now.Add(24 * time.Hour)
		if !check.FreshUntil.Equal(want) {
			t.Fatalf("fresh until = %s, want managed check-age limit %s", check.FreshUntil, want)
		}
	})
}
