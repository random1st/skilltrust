package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolatedWorkspaceUsesTheCopy(t *testing.T) {
	root := t.TempDir()
	original, other, clone := filepath.Join(root, "original"), filepath.Join(root, "other"), filepath.Join(root, "clone")
	for _, item := range []struct{ directory, module string }{{original, "example.com/original"}, {other, "example.com/other"}, {clone, "example.com/original"}} {
		if err := os.MkdirAll(item.directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(item.directory, "go.mod"), []byte("module "+item.module+"\n\ngo 1.26.8\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(item.directory, "main.go"), []byte("package example\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	work := filepath.Join(root, "original.work")
	if err := os.WriteFile(work, []byte("go 1.26.8\nuse (\n"+original+"\n"+other+"\n)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", work)
	environment, err := isolatedWorkspace(context.Background(), original, clone, root)
	if err != nil {
		t.Fatal(err)
	}
	body, err := command(context.Background(), clone, environment, "go", "list", "-f", "{{.Dir}}", "./...")
	if err != nil || !strings.Contains(string(body), filepath.Base(clone)) {
		t.Fatalf("copy was not selected: %s / %v / %v", body, err, environment)
	}
}

func TestBuildFailureIsNotBehavioralEvidence(t *testing.T) {
	started, failed := testEvents([]byte("{\"Action\":\"fail\",\"Package\":\"example\"}\n"))
	if started != 0 || len(failed) != 0 {
		t.Fatal("compiler failure counted as a killed mutant")
	}
}

func TestBehavioralFailureNamesTheFailingTest(t *testing.T) {
	started, failed := testEvents([]byte("{\"Action\":\"run\",\"Test\":\"TestExpiry\"}\n{\"Action\":\"fail\",\"Test\":\"TestExpiry\"}\n"))
	if started != 1 || len(failed) != 1 || failed[0] != "TestExpiry" {
		t.Fatal("lost behavioral failure")
	}
}
