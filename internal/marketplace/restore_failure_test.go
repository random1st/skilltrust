package marketplace

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRestoreQuarantineFailureKeepsClientManagedData(t *testing.T) {
	for _, failure := range []string{"root is a file", "namespace is a file", "names exhausted"} {
		t.Run(failure, func(t *testing.T) {
			source, root := t.TempDir(), filepath.Join(t.TempDir(), "quarantine")
			installed := InstalledPath(t.TempDir(), "acme", "runbook", "1.0.0")
			writeQuarantinePayload(t, source, "published\n")
			writeQuarantinePayload(t, installed, "my edit\n")
			for _, name := range ClientManagedRoots {
				writeQuarantinePayload(t, filepath.Join(installed, name), "client's "+name+" data\n")
			}
			now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
			switch failure {
			case "root is a file":
				if err := os.WriteFile(root, []byte("unexpected file\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "namespace is a file":
				if err := os.MkdirAll(root, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "by-target"), []byte("unexpected file\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "names exhausted":
				target, err := canonicalInstalledTarget(installed)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i <= 100; i++ {
					name := "runbook-" + now.Format(quarantineTimeLayout)
					if i > 0 {
						name += "-" + strconv.Itoa(i)
					}
					if err := os.MkdirAll(filepath.Join(quarantineTargetRoot(root, target), name), 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := Restore(installed, source, root, "runbook", now); err == nil {
				t.Fatal("restore unexpectedly succeeded despite unavailable quarantine")
			}
			assertQuarantinePayload(t, installed, "my edit\n")
			for _, name := range ClientManagedRoots {
				assertQuarantinePayload(t, filepath.Join(installed, name), "client's "+name+" data\n")
			}
		})
	}
}

func TestRestoreRollbackKeepsConcurrentClientData(t *testing.T) {
	installed, staged := t.TempDir(), t.TempDir()
	writeQuarantinePayload(t, filepath.Join(staged, ".in_use"), "existing session\n")
	writeQuarantinePayload(t, filepath.Join(staged, "node_modules"), "installed dependencies\n")
	writeQuarantinePayload(t, filepath.Join(installed, ".in_use"), "new session\n")
	err := returnClientManaged(installed, staged, []string{".in_use", "node_modules"})
	if err == nil || !strings.Contains(err.Error(), filepath.Join(staged, ".in_use")) {
		t.Fatalf("rollback must identify the retained copy when a client recreated its entry: %v", err)
	}
	assertQuarantinePayload(t, filepath.Join(staged, ".in_use"), "existing session\n")
	assertQuarantinePayload(t, filepath.Join(installed, ".in_use"), "new session\n")
	assertQuarantinePayload(t, filepath.Join(installed, "node_modules"), "installed dependencies\n")
}
