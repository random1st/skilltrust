package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	f := newRecoveryFixture(t)
	saved, digest := f.keep(t, "reviewed local change\n", time.Now())
	home, err := filepath.EvalSymlinks(f.home)
	if err != nil {
		t.Fatal(err)
	}
	result := marketplace.Result{
		Marketplace: "acme", Plugin: "runbook", Version: "1.0.0", ClientHome: home,
		Outcome: marketplace.OutcomeRestored, Quarantine: saved, OnDisk: digest,
	}
	var hook bytes.Buffer
	writeQuarantineNotice(&hook, result)
	outputs := map[string]string{
		"hook notice": hook.String(),
		"session": capture(t, func() {
			writeSessionReport([]marketplace.Result{result}, nil, false)
		}),
		"sync": capture(t, func() {
			writeReconcileReport([]marketplace.Result{result}, nil, f.home, false)
		}),
	}
	for surface, text := range outputs {
		for _, want := range []string{
			"see what changed", "to keep your version instead", "skillctl diff runbook",
			"skillctl adopt runbook", "--marketplace acme", "--quarantine-digest " + digest,
			nextCommandText([]string{"--claude-home", home}), nextCommandText([]string{"--quarantine", saved}),
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s omitted an exact executable recovery argument %q:\n%s", surface, want, text)
			}
		}
		if strings.Contains(text, "--from-quarantine") {
			t.Errorf("%s asks the user to recover a newly selected copy instead of this saved one:\n%s", surface, text)
		}
	}
}

// Legacy names identify a plugin, but not its client or marketplace. The error must show
// the candidates without claiming another plugin's copies because its name starts alike.
func TestLegacyQuarantineListsOnlyItsOwnCandidates(t *testing.T) {
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
	found, ok, err := marketplace.NewestQuarantine(quarantineRoot(), filepath.Join(home, "installed"), "runbook")
	if err == nil || ok || found != "" {
		t.Fatalf("legacy recovery = %q, %t, %v; want an explicit refusal", found, ok, err)
	}
	for _, name := range []string{"runbook-20260101T000000Z", "runbook-20260830T120000Z"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("legacy recovery error omits candidate %s: %v", name, err)
		}
	}
	if strings.Contains(err.Error(), "runbook-tests") {
		t.Fatalf("legacy recovery claims another plugin's copy: %v", err)
	}
}
