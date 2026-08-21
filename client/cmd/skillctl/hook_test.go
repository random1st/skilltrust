package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
)

func writeSkill(t *testing.T, root, name string) {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: " + name + "\ndescription: A demo skill.\n---\n\nBody.\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func pin(t *testing.T, root string) {
	t.Helper()
	lock, err := lockfile.Build(root, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Save(filepath.Join(root, lockfile.FileName)); err != nil {
		t.Fatal(err)
	}
}

// A lock that is absent and a lock that cannot be read are different facts and must not be
// reported the same way. Conflating them hands an attacker a silent off switch: corrupt the
// file and the session-start check disappears without a trace.
func TestVerifyRootsSeparatesMissingFromUnreadable(t *testing.T) {
	unpinned := t.TempDir()
	writeSkill(t, unpinned, "alpha")

	pinned := t.TempDir()
	writeSkill(t, pinned, "alpha")
	pin(t, pinned)

	corrupt := t.TempDir()
	writeSkill(t, corrupt, "alpha")
	if err := os.WriteFile(filepath.Join(corrupt, lockfile.FileName),
		[]byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	reports, broken := verifyRoots([]string{unpinned, pinned, corrupt})

	if len(reports) != 1 {
		t.Fatalf("only the pinned tree should produce a report, got %d", len(reports))
	}
	if len(broken) != 1 {
		t.Fatalf("the corrupt lock must be reported, got %v", broken)
	}
	if !strings.Contains(broken[0], corrupt) {
		t.Fatalf("broken = %v", broken)
	}
}

func TestHookReportNamesTheChangedFile(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "alpha")
	pin(t, root)

	skillFile := filepath.Join(root, "alpha", "SKILL.md")
	existing, err := os.ReadFile(skillFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skillFile, append(existing, []byte("\nextra\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	reports, broken := verifyRoots([]string{root})
	buffer := &strings.Builder{}
	writeHookReport(buffer, reports, broken)

	output := buffer.String()
	for _, want := range []string{"alpha", "modified SKILL.md", "detection, not enforcement"} {
		if !strings.Contains(output, want) {
			t.Fatalf("report is missing %q:\n%s", want, output)
		}
	}
}

// Following a symlink is normal, hiding it is not: `cp -R` of a symlinked directory
// produces another symlink, so writes meant for a sandbox land on the original.
func TestResolvePathReportsSymlinkHops(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "looks-like-a-copy")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	resolved, note, err := resolvePath(link)
	if err != nil {
		t.Fatal(err)
	}
	if note == "" {
		t.Fatal("crossing a symlink must be reported")
	}
	expected, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != expected {
		t.Fatalf("resolved = %s, want %s", resolved, expected)
	}

	// Compare against the already-resolved path: on macOS /var is itself a symlink to
	// /private/var, so a temp directory legitimately produces a note.
	if _, note, err := resolvePath(expected); err != nil || note != "" {
		t.Fatalf("an already-resolved path must produce no note: note=%q err=%v", note, err)
	}
}
