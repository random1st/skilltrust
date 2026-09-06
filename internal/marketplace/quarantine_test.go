package marketplace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQuarantineSeparatesInstalledTargets(t *testing.T) {
	root, home, otherHome, source := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	writeQuarantinePayload(t, source, "published\n")
	var copies []string
	targets := []string{
		InstalledPath(home, "one", "runbook", "1.0.0"),
		InstalledPath(home, "two", "runbook", "1.0.0"),
		InstalledPath(otherHome, "one", "runbook", "1.0.0"),
		InstalledPath(home, "one", "runbook", "2.0.0"),
	}
	for i, target := range targets {
		writeQuarantinePayload(t, target, "edit "+strconv.Itoa(i)+"\n")
		copy, err := Restore(target, source, root, "runbook", time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		copies = append(copies, copy)
	}
	for i, target := range targets {
		found, ok, err := NewestQuarantine(root, target, "runbook")
		if err != nil || !ok || found != copies[i] {
			t.Fatalf("target %s: selected %q, %t, %v; want %q", target, found, ok, err, copies[i])
		}
		if i > 0 {
			if err := Reclaim(found, targets[0]); err == nil {
				t.Fatalf("Reclaim accepted target %d's copy for target 0", i)
			}
			assertQuarantinePayload(t, targets[0], "published\n")
		}
		if wrong, ok, err := NewestQuarantine(root, target, "another-name"); err == nil || ok || wrong != "" {
			t.Fatalf("lookup accepted another plugin name: %q, %t, %v", wrong, ok, err)
		}
		assertQuarantinePayload(t, found, "edit "+strconv.Itoa(i)+"\n")
	}
	for i, target := range targets {
		if err := Reclaim(copies[i], target); err != nil {
			t.Fatal(err)
		}
		assertQuarantinePayload(t, target, "edit "+strconv.Itoa(i)+"\n")
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 1 || entries[0].Name() != "SKILL.md" {
			t.Fatalf("reclaimed payload gained provenance or other files: %v (%v)", entries, err)
		}
	}
}

func TestNewestQuarantineRejectsDamagedProvenance(t *testing.T) {
	for _, damage := range []string{"missing", "invalid json", "unknown schema", "wrong target", "wrong plugin", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			root, source := t.TempDir(), t.TempDir()
			target := InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
			writeQuarantinePayload(t, source, "published\n")
			var latest string
			for i := 0; i < 2; i++ {
				writeQuarantinePayload(t, target, "edit "+strconv.Itoa(i)+"\n")
				var err error
				latest, err = Restore(target, source, root, "runbook", time.Date(2026, 9, 5, 12, i, 0, 0, time.UTC))
				if err != nil {
					t.Fatal(err)
				}
			}
			// A valid older target copy and a legacy copy must not hide broken provenance.
			legacy := filepath.Join(root, "runbook-20260905T130000Z")
			writeQuarantinePayload(t, legacy, "legacy edit\n")
			metadata := latest + ".json"
			body, err := os.ReadFile(metadata)
			if err != nil {
				t.Fatal(err)
			}
			var provenance quarantineProvenance
			if err := json.Unmarshal(body, &provenance); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing":
				err = os.Remove(metadata)
			case "invalid json":
				err = os.WriteFile(metadata, []byte("{"), 0o600)
			case "symlink":
				other := filepath.Join(t.TempDir(), "provenance.json")
				if err := os.WriteFile(other, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(metadata); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(other, metadata)
				if err != nil {
					t.Skipf("cannot create symlinks here: %v", err)
				}
			default:
				switch damage {
				case "unknown schema":
					provenance.Schema++
				case "wrong target":
					provenance.Installed += "-other-client"
				case "wrong plugin":
					provenance.Plugin = "other-plugin"
				}
				body, _ = json.Marshal(provenance)
				err = os.WriteFile(metadata, body, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			found, ok, err := NewestQuarantine(root, target, "runbook")
			if err == nil || ok || found != "" || !strings.Contains(err.Error(), "provenance") {
				t.Fatalf("damaged provenance silently fell back: %q, %t, %v", found, ok, err)
			}
			if err := Reclaim(latest, target); err == nil {
				t.Fatal("explicit recovery ignored damaged provenance")
			}
			assertQuarantinePayload(t, target, "published\n")
			assertQuarantinePayload(t, latest, "edit 1\n")
			assertQuarantinePayload(t, legacy, "legacy edit\n")
		})
	}
}

func TestNewestQuarantineNormalizesClientAliases(t *testing.T) {
	root, home, source := t.TempDir(), t.TempDir(), t.TempDir()
	alias := filepath.Join(t.TempDir(), "client-alias")
	if err := os.Symlink(home, alias); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	target := InstalledPath(home, "acme", "runbook", "1.0.0")
	writeQuarantinePayload(t, source, "published\n")
	writeQuarantinePayload(t, target, "edit\n")
	copy, err := Restore(InstalledPath(alias, "acme", "runbook", "1.0.0"), source, root, "runbook", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, InstalledPath(alias, "acme", "runbook", "1.0.0"), filepath.Dir(target) + "/./1.0.0"} {
		found, ok, err := NewestQuarantine(root, path, "runbook")
		if err != nil || !ok || found != copy {
			t.Fatalf("client alias %s did not find the same target: %q, %t, %v", path, found, ok, err)
		}
	}
	quarantineAlias := filepath.Join(t.TempDir(), "backup-alias")
	if err := os.Symlink(filepath.Dir(copy), quarantineAlias); err != nil {
		t.Fatal(err)
	}
	wrongTarget := InstalledPath(home, "another", "runbook", "1.0.0")
	writeQuarantinePayload(t, wrongTarget, "another marketplace\n")
	if err := Reclaim(filepath.Join(quarantineAlias, filepath.Base(copy)), wrongTarget); err == nil {
		t.Fatal("a quarantine path alias bypassed the installed target check")
	}
	assertQuarantinePayload(t, wrongTarget, "another marketplace\n")
}

func TestNewestQuarantineOrdersTimestampsAndCollisionCounters(t *testing.T) {
	root, source := t.TempDir(), t.TempDir()
	target := InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
	writeQuarantinePayload(t, source, "published\n")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		writeQuarantinePayload(t, target, "edit "+strconv.Itoa(i)+"\n")
		when := now
		if i == 0 {
			when = now.Add(-time.Hour)
		}
		if _, err := Restore(target, source, root, "runbook", when); err != nil {
			t.Fatal(err)
		}
	}
	found, ok, err := NewestQuarantine(root, target, "runbook")
	if err != nil || !ok {
		t.Fatalf("latest quarantine: %q, %t, %v", found, ok, err)
	}
	assertQuarantinePayload(t, found, "edit 11\n")
}

func writeQuarantinePayload(t *testing.T, directory, body string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertQuarantinePayload(t *testing.T, directory, want string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(directory, "SKILL.md"))
	if err != nil || string(body) != want {
		t.Fatalf("%s: skill = %q (%v), want %q", directory, body, err, want)
	}
}
