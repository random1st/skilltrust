package marketplace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reviewedCopyFixture(t *testing.T) (installed, saved, reviewed, published string) {
	t.Helper()
	source := t.TempDir()
	installed = InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
	writeQuarantinePayload(t, source, "published\n")
	writeQuarantinePayload(t, installed, "reviewed edit\n")
	var err error
	reviewed, _, err = DigestInstalled(installed)
	if err != nil {
		t.Fatal(err)
	}
	saved, err = Restore(installed, source, t.TempDir(), "runbook", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	published, _, err = DigestInstalled(installed)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestReclaimVerifiedKeepsExactPayloadAndClientData(t *testing.T) {
	installed, saved, reviewed, published := reviewedCopyFixture(t)
	for _, name := range ClientManagedRoots {
		writeQuarantinePayload(t, filepath.Join(installed, name), "live "+name+"\n")
	}
	if err := ReclaimVerified(saved, installed, "runbook", reviewed, published); err != nil {
		t.Fatal(err)
	}
	assertQuarantinePayload(t, installed, "reviewed edit\n")
	for _, name := range ClientManagedRoots {
		assertQuarantinePayload(t, filepath.Join(installed, name), "live "+name+"\n")
	}
	if _, err := os.Lstat(saved); !os.IsNotExist(err) {
		t.Fatalf("recovered copy still counted as pending: %v", err)
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(installed), ".skilltrust-reclaim-*")); err != nil || len(matches) != 0 {
		t.Fatalf("successful recovery left staging behind: %v, %v", matches, err)
	}
}

func TestReclaimVerifiedRefusesChangedReviewedOrInstalledBytes(t *testing.T) {
	for _, change := range []string{"reviewed", "installed", "missing digest", "provenance"} {
		t.Run(change, func(t *testing.T) {
			installed, saved, reviewed, published := reviewedCopyFixture(t)
			wantInstalled, wantSaved := "published\n", "reviewed edit\n"
			switch change {
			case "reviewed":
				wantSaved = "unreviewed later edit\n"
				writeQuarantinePayload(t, saved, wantSaved)
			case "installed":
				wantInstalled = "fresh installed edit\n"
				writeQuarantinePayload(t, installed, wantInstalled)
			case "missing digest":
				reviewed = ""
			case "provenance":
				if err := os.WriteFile(saved+".json", []byte("broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeQuarantinePayload(t, filepath.Join(installed, ".in_use"), "live session\n")
			if err := ReclaimVerified(saved, installed, "runbook", reviewed, published); err == nil {
				t.Fatal("recovered despite changed or unproven bytes")
			}
			assertQuarantinePayload(t, installed, wantInstalled)
			assertQuarantinePayload(t, saved, wantSaved)
			assertQuarantinePayload(t, filepath.Join(installed, ".in_use"), "live session\n")
		})
	}
}

func TestReclaimVerifiedRollsBackEarlierClientMovesOnCollision(t *testing.T) {
	installed, saved, reviewed, published := reviewedCopyFixture(t)
	writeQuarantinePayload(t, filepath.Join(installed, ".in_use"), "live session\n")
	writeQuarantinePayload(t, filepath.Join(installed, "node_modules"), "current dependency\n")
	writeQuarantinePayload(t, filepath.Join(saved, "node_modules"), "saved dependency\n")
	if err := ReclaimVerified(saved, installed, "runbook", reviewed, published); err == nil {
		t.Fatal("recovery replaced an existing client-owned entry")
	}
	assertQuarantinePayload(t, installed, "published\n")
	assertQuarantinePayload(t, saved, "reviewed edit\n")
	assertQuarantinePayload(t, filepath.Join(installed, ".in_use"), "live session\n")
	assertQuarantinePayload(t, filepath.Join(installed, "node_modules"), "current dependency\n")
	assertQuarantinePayload(t, filepath.Join(saved, "node_modules"), "saved dependency\n")
	if _, err := os.Lstat(filepath.Join(saved, ".in_use")); !os.IsNotExist(err) {
		t.Fatalf("a failed recovery stranded live locks in quarantine: %v", err)
	}
}

func TestQuarantinePayloadRejectsOtherHomesAndUnboundPaths(t *testing.T) {
	installed, saved, _, _ := reviewedCopyFixture(t)
	other := InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
	writeQuarantinePayload(t, other, "published\n")
	if _, _, err := QuarantinePayload(saved, other, "runbook"); err == nil {
		t.Fatal("review accepted another client's copy")
	}
	legacy := filepath.Join(t.TempDir(), "runbook-20260905T120000Z")
	writeQuarantinePayload(t, legacy, "legacy edit\n")
	if _, _, err := QuarantinePayload(legacy, installed, "runbook"); err == nil {
		t.Fatal("an explicit path invented missing legacy provenance")
	}
	realCopy := saved + "-original"
	if err := os.Rename(saved, realCopy); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realCopy, saved); err != nil {
		t.Skipf("filesystem cannot create symlinks: %v", err)
	}
	if _, _, err := QuarantinePayload(saved, installed, "runbook"); err == nil {
		t.Fatal("a root symlink was mistaken for the provenance-bound saved directory")
	}
}

func TestReconcileKeepsClientHomeLocal(t *testing.T) {
	home := t.TempDir()
	digest := install(t, home, "acme", "runbook", "1.0.0", "published\n")
	results := Reconcile(snapshotOf("acme", "runbook", "1.0.0", digest), Options{ClaudeHome: home})
	want, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ClientHome != want {
		t.Fatalf("local recovery target is missing: %+v", results)
	}
	body, err := json.Marshal(results)
	if err != nil || strings.Contains(string(body), want) || strings.Contains(string(body), "client_home") {
		t.Fatalf("private client path entered the report projection: %s, %v", body, err)
	}
}
