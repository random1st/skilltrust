package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

// fleetDirectory writes signed events into a directory and pins the machine key that
// signed them, returning the directory to point `skillctl fleet` at.
func fleetDirectory(t *testing.T, events ...report.Event) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.SaveTrustedKeys(defaultTrustedKeys(),
		map[string]ed25519.PublicKey{"laptop": public}); err != nil {
		t.Fatal(err)
	}

	directory := filepath.Join(home, "fleet")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	spool := report.Spool{Directory: directory}
	for _, event := range events {
		event.Complete()
		envelope, err := report.Sign(event, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := spool.Add(envelope, event.At, string(event.Kind)); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

// A fleet where every machine knowingly runs unsigned bytes must not print like a fleet
// with nothing to report.
//
// `skillctl fleet` iterated a fixed list of kinds that KindAdapted was not in, so adapted
// events were counted into a map nobody read and then dropped: two machines, two
// adoptions, and the page said "0 events" and exited clean. This is the console the README
// advertises for the git-and-no-server path, so on that path the one state the design
// calls "never quiet" was silent everywhere.
func TestFleetShowsWhatMachinesAdopted(t *testing.T) {
	now := time.Now().UTC()
	directory := fleetDirectory(t,
		report.Event{Kind: report.KindAdapted, At: now, Machine: "laptop-1", Host: "laptop-1",
			Marketplace: "acme", Plugin: "runbook", Detail: "our staging URL (adopted 2mo ago)"},
		report.Event{Kind: report.KindAdapted, At: now, Machine: "laptop-2", Host: "laptop-2",
			Marketplace: "acme", Plugin: "handbook", Detail: "we removed the pager step"},
	)

	var code int
	output := capture(t, func() { code = runFleet([]string{directory}) })

	for _, want := range []string{"adapted", "runbook", "handbook", "our staging URL"} {
		if !strings.Contains(output, want) {
			t.Fatalf("the fleet page never mentions %q:\n%s", want, output)
		}
	}
	// Low severity earns not flipping the exit code; it does not earn being absent.
	if code != exitClean {
		t.Fatalf("exit = %d, want %d — an adopted plugin is a state, not something "+
			"outstanding", code, exitClean)
	}
}

// The same adoption is reported every session, forever. Counting events would read as
// hundreds of modified copies where there is one, so the page counts distinct plugins.
func TestRepeatedAdoptionsCountAsOnePlugin(t *testing.T) {
	now := time.Now().UTC()
	var events []report.Event
	for session := 0; session < 7; session++ {
		events = append(events, report.Event{
			Kind: report.KindAdapted, At: now.Add(-time.Duration(session) * time.Hour),
			Machine: "laptop-1", Host: "laptop-1",
			Marketplace: "acme", Plugin: "runbook", Detail: "our staging URL",
		})
	}
	directory := fleetDirectory(t, events...)

	output := capture(t, func() { runFleet([]string{directory}) })

	if !strings.Contains(output, "adapted          1 plugin") {
		t.Fatalf("seven sessions of one adoption must read as one plugin:\n%s", output)
	}
}
