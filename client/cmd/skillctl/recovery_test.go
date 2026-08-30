package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/internal/marketplace"
)

// The session hook told people their change had not survived in the same breath as
// preserving it: the trailer was printed whenever anything was spoken about, and an
// adapted plugin is spoken about by design. sync.go and preskill.go were already right;
// this renderer was the one left behind, which is the shape a partial fix always takes.
func TestTheSessionHookDoesNotSayAnAdoptedChangeWasUndone(t *testing.T) {
	adaptedOnly := []marketplace.Result{{
		Marketplace: "acme", Plugin: "deploy-runbook", Version: "1.0.0",
		Outcome: marketplace.OutcomeAdapted, Adapted: "our staging URL, not theirs",
	}}
	output := capture(t, func() { writeSessionReport(adaptedOnly, nil, false) })

	if strings.Contains(output, "do not survive") {
		t.Fatalf("an adapted-only session says the change did not survive, immediately "+
			"after keeping it:\n%s", output)
	}
	if !strings.Contains(output, "our staging URL, not theirs") {
		t.Fatalf("the reason is the point of the line and is missing:\n%s", output)
	}

	// The trailer is still true — and still printed — when something really was overridden.
	restored := append(adaptedOnly, marketplace.Result{
		Marketplace: "acme", Plugin: "handbook", Version: "1.0.0",
		Outcome: marketplace.OutcomeRestored, Quarantine: "/tmp/handbook-x",
	})
	output = capture(t, func() { writeSessionReport(restored, nil, false) })
	if !strings.Contains(output, "do not survive") {
		t.Fatalf("a restored plugin must still carry the warning:\n%s", output)
	}
}

// Every surface that puts a copy back must offer the recovery that works from where the
// reader now stands. A plain `skillctl adopt` after a restore adopts the publisher's
// bytes — the opposite of what the person wanted — because their own copy is already in
// quarantine by the time they read the hint.
func TestRestoreHintsPointAtTheRecoveryThatWorks(t *testing.T) {
	for surface, file := range map[string]string{
		"the sync report":        "sync.go",
		"the session-start hook": "sessionhook.go",
		"the pre-skill hook":     "preskill.go",
	} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v", surface, err)
		}
		text := string(body)
		if !strings.Contains(text, "to keep your version instead") {
			t.Errorf("%s (%s) no longer offers a way to keep a change it put back",
				surface, file)
			continue
		}
		if !strings.Contains(text, "--from-quarantine") {
			t.Errorf("%s (%s) still tells people to adopt what is installed, which after a "+
				"restore is the published copy", surface, file)
		}
	}
}

// newestQuarantine picks by the timestamp in the directory name, and must not claim
// another plugin's quarantine because its name starts the same way.
func TestNewestQuarantinePicksTheLatestAndOnlyItsOwn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)
	for _, name := range []string{
		"runbook-20260101T000000Z",
		"runbook-20260830T120000Z",
		"runbook-tests-20260901T000000Z",
	} {
		if err := os.MkdirAll(filepath.Join(quarantineRoot(), name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	found, ok := newestQuarantine("runbook")
	if !ok {
		t.Fatal("nothing found for a plugin with two quarantined copies")
	}
	if filepath.Base(found) != "runbook-20260830T120000Z" {
		t.Fatalf("newestQuarantine = %s; want the later timestamp, and never the copy "+
			"belonging to runbook-tests", found)
	}
}
