package marketplace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingQuarantinesOutliveCleanChecksAndRemovedClients(t *testing.T) {
	root, source := t.TempDir(), t.TempDir()
	target := InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
	writeQuarantinePayload(t, source, "published\n")
	writeQuarantinePayload(t, target, "my edit\n")
	saved, err := Restore(target, source, root, "runbook", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(saved + ".json")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if count, err := PendingQuarantines(root); err != nil || count != 1 {
			t.Fatalf("read %d: saved edit count = %d (%v)", i, count, err)
		}
	}
	listed, err := ListPendingQuarantines(root)
	canonical, targetErr := canonicalInstalledTarget(target)
	if err != nil || targetErr != nil || len(listed) != 1 || listed[0].Installed != canonical || listed[0].Plugin != "runbook" || listed[0].Path != saved {
		t.Fatalf("pending list lost its exact target: %+v (%v, %v)", listed, err, targetErr)
	}
	assertQuarantinePayload(t, saved, "my edit\n")
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if count, err := PendingQuarantines(root); err != nil || count != 1 {
		t.Fatalf("uninstall hid saved edits: %d (%v)", count, err)
	}
	if err := Reclaim(saved, target); err != nil {
		t.Fatal(err)
	}
	if count, err := PendingQuarantines(root); err != nil || count != 0 {
		t.Fatalf("consumed payload still marks a saved edit: %d (%v)", count, err)
	}
	remaining, err := os.ReadFile(saved + ".json")
	if err != nil || string(remaining) != string(metadata) {
		t.Fatalf("read-only count changed the provenance: %v", err)
	}
}

func TestPendingQuarantinesDoNotTreatDamagedHistoryAsEmpty(t *testing.T) {
	for _, damage := range []string{"missing sidecar", "invalid json", "wrong schema", "wrong target", "wrong name", "legacy", "payload symlink", "root file"} {
		t.Run(damage, func(t *testing.T) {
			root, source := t.TempDir(), t.TempDir()
			target := InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
			writeQuarantinePayload(t, source, "published\n")
			writeQuarantinePayload(t, target, "my edit\n")
			saved, err := Restore(target, source, root, "runbook", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing sidecar":
				err = os.Remove(saved + ".json")
			case "invalid json":
				err = os.WriteFile(saved+".json", []byte("{"), 0o600)
			case "legacy":
				err = os.Mkdir(filepath.Join(root, "runbook-20260905T120000Z"), 0o700)
			case "payload symlink":
				moved := filepath.Join(t.TempDir(), "my-edit")
				if err := os.Rename(saved, moved); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(moved, saved)
			case "root file":
				root = filepath.Join(t.TempDir(), "quarantine")
				err = os.WriteFile(root, []byte("not a directory"), 0o600)
			default:
				body, err := os.ReadFile(saved + ".json")
				if err != nil {
					t.Fatal(err)
				}
				var provenance quarantineProvenance
				if err := json.Unmarshal(body, &provenance); err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "wrong schema":
					provenance.Schema++
				case "wrong target":
					provenance.Installed += "-other-client"
				case "wrong name":
					provenance.Plugin = "other-plugin"
				}
				body, err = json.Marshal(provenance)
				if err == nil {
					err = os.WriteFile(saved+".json", body, 0o600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if count, err := PendingQuarantines(root); err == nil {
				t.Fatalf("damaged history reported as %d healthy saved copies", count)
			}
		})
	}
}

func TestPendingQuarantinesColdReadDoesNotCreateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	if count, err := PendingQuarantines(root); count != 0 || err != nil {
		t.Fatalf("cold count = %d (%v)", count, err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("status inspection created state: %v", err)
	}
}
