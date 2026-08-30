package main

import (
	"os"
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
	sources := map[string]string{
		"the sync report":        "sync.go",
		"the session-start hook": "sessionhook.go",
		"the pre-skill hook":     "preskill.go",
		"the fleet event":        "events.go",
	}
	for surface, file := range sources {
		body, err := os.ReadFile("cmd/skillctl/" + file)
		if err != nil {
			body, err = os.ReadFile(file)
		}
		if err != nil {
			t.Fatalf("%s: %v", surface, err)
		}
		text := string(body)
		if !strings.Contains(text, "OutcomeAdapted") {
			t.Errorf("%s (%s) does not handle an adopted plugin at all", surface, file)
			continue
		}
		if !strings.Contains(text, "result.Adapted") {
			t.Errorf("%s (%s) handles adoption but never shows the reason, which lives in "+
				"Adapted rather than Detail", surface, file)
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
	for surface, file := range map[string]string{
		"the sync report":        "sync.go",
		"the session-start hook": "sessionhook.go",
		"the pre-skill hook":     "preskill.go",
	} {
		body, err := os.ReadFile("cmd/skillctl/" + file)
		if err != nil {
			body, err = os.ReadFile(file)
		}
		if err != nil {
			t.Fatalf("%s: %v", surface, err)
		}
		text := string(body)
		if !strings.Contains(text, "OutcomeRestored") {
			continue // this surface does not report an undo
		}
		if !strings.Contains(text, "skillctl adopt %s") {
			t.Errorf("%s (%s) undoes someone's work without telling them how to keep it",
				surface, file)
		}
	}
}

// When the publisher ships a new version over somebody's patch, both versions end up on
// disk and nobody would guess the second path. Without the diff line, re-applying a patch
// across an upstream release is archaeology: find the quarantine directory, work out where
// the new copy landed, compare them by hand. This is the one place the tool can turn that
// into a paste, and it is the whole of what exists for keeping a patch across updates.
func TestBeingReplacedShowsHowToSeeWhatChanged(t *testing.T) {
	body, err := os.ReadFile("cmd/skillctl/sync.go")
	if err != nil {
		body, err = os.ReadFile("sync.go")
	}
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "diff -ru") {
		t.Error("a replaced copy is reported without any way to see what changed")
	}
	if !strings.Contains(text, "marketplace.InstalledPath(") {
		t.Error("the diff names no second path, so the reader still has to find it")
	}
}
