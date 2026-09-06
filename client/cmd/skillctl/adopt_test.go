package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/internal/marketplace"
)

// Four surfaces render a reconciliation outcome: the sync report, the session-start hook,
// the pre-skill hook, and the fleet event. An adopted plugin's reason lives in a different
// field from every other outcome's detail, so each surface has to be taught separately -
// and each one that is not shows a divergence with no account of it, which is precisely the
// state adopting exists to replace. Two of the four had already been missed once.
func TestEverySurfaceShowsWhyAPluginWasAdopted(t *testing.T) {
	result := marketplace.Result{Marketplace: "acme", Plugin: "runbook", Outcome: marketplace.OutcomeAdapted,
		Adapted: "Our staging URL needs a different port", Detail: "This is not the reason"}
	var preSkill bytes.Buffer
	if code := decideTo(result, false, &preSkill); code != exitClean {
		t.Fatalf("an accepted local change was blocked: %d", code)
	}
	events := collectEvents([]marketplace.Result{result}, nil, time.Now())
	if len(events) != 1 {
		t.Fatalf("missing adoption event: %+v", events)
	}
	for surface, text := range map[string]string{
		"sync":      capture(t, func() { writeReconcileReport([]marketplace.Result{result}, nil, t.TempDir(), false) }),
		"session":   capture(t, func() { writeSessionReport([]marketplace.Result{result}, nil, false) }),
		"pre-skill": preSkill.String(), "fleet": events[0].Detail,
	} {
		if !strings.Contains(text, result.Adapted) {
			t.Errorf("%s omitted the actual reason: %s", surface, text)
		}
	}
}

// age answers "is this recent, or did somebody leave it here" and must not claim precision
// it does not have.
func TestAgeReadsAsARoughAnswer(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for expected, since := range map[string]time.Time{
		"today":    now.Add(-2 * time.Hour),
		"10d ago":  now.AddDate(0, 0, -10),
		"24mo ago": now.AddDate(-2, 0, 0),
		"unknown":  {},
	} {
		if got := age(since, now); got != expected {
			t.Errorf("age(%v) = %q, want %q", since, got, expected)
		}
	}
}

// An adoption is refused for anything it cannot honestly describe, so a person never ends
// up with a record pointing at bytes that are not there or must not run.
func TestAdoptionIsRefusedForWhatItCannotDescribe(t *testing.T) {
	for name, result := range map[string]marketplace.Result{
		"already matching what was published": {Plugin: "p", Outcome: marketplace.OutcomeVerified},
		"revoked":                             {Plugin: "p", Outcome: marketplace.OutcomeRevoked, Detail: "bad"},
		"not installed":                       {Plugin: "p", Outcome: marketplace.OutcomeAbsent},
		"unreadable":                          {Plugin: "p", Outcome: marketplace.OutcomeUnverifiable},
	} {
		if _, err := pick([]marketplace.Result{result}, "", "p"); err == nil {
			t.Errorf("adopting something %s must be refused", name)
		}
	}
	if _, err := pick(nil, "", "missing"); err == nil {
		t.Error("adopting a plugin no catalog publishes must be refused")
	}
	if _, err := pick([]marketplace.Result{
		{Plugin: "p", Marketplace: "one", Outcome: marketplace.OutcomeChanged},
		{Plugin: "p", Marketplace: "two", Outcome: marketplace.OutcomeChanged},
	}, "", "p"); err == nil || !strings.Contains(err.Error(), "--marketplace") {
		t.Errorf("an ambiguous name must be refused with a way to disambiguate, got %v", err)
	}
}

// Nobody reads documentation to find out why their file keeps changing back. The one
// moment a person will read anything is the moment their work is undone, so that is where
// the command that keeps it has to be — in every message that reports an undo, not in help
// text they would have had to find before they knew they needed it.
func TestLosingYourWorkTellsYouHowToKeepIt(t *testing.T) {
	f := newRecoveryFixture(t)
	saved, digest := f.keep(t, "intentional change\n", time.Now())
	result := marketplace.Result{Marketplace: "acme", Plugin: "runbook", Version: "1.0.0", ClientHome: f.home,
		Outcome: marketplace.OutcomeRestored, Quarantine: saved, OnDisk: digest}
	var preSkill bytes.Buffer
	if code := decideTo(result, false, &preSkill); code != exitClean {
		t.Fatalf("restored, verified plugin was blocked: %d", code)
	}
	for _, want := range []string{"skillctl diff runbook", "skillctl adopt runbook", "--quarantine-digest " + digest,
		nextCommandText([]string{"--quarantine", saved})} {
		if !strings.Contains(preSkill.String(), want) {
			t.Errorf("pre-skill restoration omitted %q: %s", want, preSkill.String())
		}
	}
}

// When the publisher ships a new version over somebody's patch, both versions end up on
// disk and nobody would guess the second path. Without the diff line, re-applying a patch
// across an upstream release is archaeology: find the quarantine directory, work out where
// the new copy landed, compare them by hand. This is the one place the tool can turn that
// into a paste, and it is the whole of what exists for keeping a patch across updates.
func TestBeingReplacedShowsHowToSeeWhatChanged(t *testing.T) {
	f := newRecoveryFixture(t)
	saved, digest := f.keep(t, "old intentional change\n", time.Now())
	result := marketplace.Result{Marketplace: "acme", Plugin: "runbook", Version: "1.0.0", ClientHome: f.home,
		Outcome: marketplace.OutcomeRestored, Quarantine: saved, OnDisk: digest, Lapsed: true}
	text := capture(t, func() { writeReconcileReport([]marketplace.Result{result}, nil, f.home, false) })
	if !strings.Contains(text, "skillctl diff runbook") || !strings.Contains(text, nextCommandText([]string{"--quarantine", saved})) {
		t.Fatalf("lapsed change has no exact comparison: %s", text)
	}
	if strings.Contains(text, "skillctl adopt") {
		t.Fatalf("suggested adopting an obsolete change onto a new publisher version: %s", text)
	}
}
