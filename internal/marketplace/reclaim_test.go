package marketplace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/catalog"
)

// Revoking the digest a machine reports running must stop those bytes.
//
// Only the published digest was checked, so revocation was inert against exactly the
// copies an organisation would want to stop: the modified one on somebody's laptop, whose
// digest the dashboard shows and whose digest security pastes into `catalog revoke`. The
// command accepted it, the catalog carried it, every machine fetched it, and nothing
// happened — while the console said the skill was stopped.
func TestRevokingTheDigestOnDiskStopsIt(t *testing.T) {
	home := t.TempDir()
	published := install(t, home, "acme", "runbook", "1.0.0", "published\n")
	mine := install(t, home, "acme", "runbook", "1.0.0", "mine\n")

	snapshot := snapshotOf("acme", "runbook", "1.0.0", published)
	snapshot.Revoked = []catalog.Entry{{Digest: mine, Reason: "unreviewed local edit"}}

	now := time.Now().UTC()
	adopted := Adoptions{Entries: []Adoption{{
		Marketplace: "acme", Plugin: "runbook", From: published, Local: mine,
		Since: now.AddDate(0, -1, 0), Reason: "our staging URL",
	}}}

	result := Reconcile(snapshot, Options{ClaudeHome: home, Adopted: adopted, Now: now})[0]
	if result.Outcome != OutcomeRevoked {
		t.Fatalf("outcome = %q, want %q — an adoption survived the revocation of its own "+
			"bytes, which makes revocation optional on the machines that edited a skill",
			result.Outcome, OutcomeRevoked)
	}
	if result.Detail != "unreviewed local edit" {
		t.Fatalf("detail = %q, want the revocation's reason", result.Detail)
	}
}

// Reclaim is the way back from a restore. Without it the advertised recovery dead-ended:
// the hint said "adopt this to keep it", but by the time anyone read it their bytes were
// in quarantine and the installed copy matched the signature, so adopt truthfully answered
// that there was nothing to adopt.
func TestReclaimPutsAQuarantinedCopyBack(t *testing.T) {
	home := t.TempDir()
	installed := InstalledPath(home, "acme", "runbook", "1.0.0")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, "SKILL.md"),
		[]byte("the publisher's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The client wrote into the installed copy after the restore, so those entries belong
	// to the copy coming back — dropping them breaks the plugin or a live session's lock.
	if err := os.MkdirAll(filepath.Join(installed, ".in_use"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, ".in_use", "1234"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	quarantined := filepath.Join(t.TempDir(), "runbook-20260830T120000Z")
	if err := os.MkdirAll(quarantined, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quarantined, "SKILL.md"),
		[]byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Reclaim(quarantined, installed); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(installed, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "mine\n" {
		t.Fatalf("installed copy = %q, want the quarantined bytes back", body)
	}
	if _, err := os.Stat(filepath.Join(installed, ".in_use", "1234")); err != nil {
		t.Fatalf("a session lock did not survive taking the copy back: %v", err)
	}
	if _, err := os.Stat(quarantined); !os.IsNotExist(err) {
		t.Fatal("the quarantined directory must be consumed, not left as a second copy")
	}
}

// An upstream version bump leaves the adoption behind: the reconciler only ever digests
// the version the catalog signs, so nothing examines the adopted release again. The
// version line is the last moment anyone will be told, so it must say what happened to
// the decision they made rather than reporting a bare version difference.
func TestAVersionBumpSaysWhatBecameOfTheAdoption(t *testing.T) {
	home := t.TempDir()
	install(t, home, "acme", "runbook", "1.0.0", "mine\n")

	now := time.Now().UTC()
	adopted := Adoptions{Entries: []Adoption{{
		Marketplace: "acme", Plugin: "runbook", Version: "1.0.0",
		From: "sha256:whatever", Local: "sha256:mine",
		Since: now.AddDate(0, -2, 0), Reason: "our staging URL",
	}}}

	result := Reconcile(snapshotOf("acme", "runbook", "1.1.0", "sha256:new"), Options{
		ClaudeHome: home, Adopted: adopted, Now: now,
	})[0]
	if result.Outcome != OutcomeOtherVersion {
		t.Fatalf("outcome = %q, want %q", result.Outcome, OutcomeOtherVersion)
	}
	for _, want := range []string{"adopted", "1.0.0", "1.1.0", "our staging URL"} {
		if !strings.Contains(result.Detail, want) {
			t.Fatalf("the version line never mentions %q, so the adoption ends in silence:\n  %s",
				want, result.Detail)
		}
	}
}
