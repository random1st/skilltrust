package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHomeHonoursTheEnvironment(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", "/tmp/example-home")
	if Home() != "/tmp/example-home" {
		t.Fatalf("Home = %s", Home())
	}
	if defaultSigningKey() != filepath.Join("/tmp/example-home", "signer.key") {
		t.Fatalf("signing key = %s", defaultSigningKey())
	}
}

// Four candidate paths routinely resolve to one directory — ~/.claude/skills is commonly a
// symlink to ~/.agents/skills — and reporting the same tree twice would inflate every count
// on the status screen.
func TestSkillRootsDeduplicateByResolvedPath(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, ".agents", "skills")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	t.Chdir(base)
	t.Setenv("HOME", base)

	roots, err := resolveSkillRoots("")
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 {
		t.Fatalf("roots = %v; the same directory reached two ways must appear once", roots)
	}
}

func TestExplicitPathWins(t *testing.T) {
	directory := t.TempDir()
	roots, err := resolveSkillRoots(directory)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0] != resolved {
		t.Fatalf("roots = %v, want [%s]", roots, resolved)
	}
}

func TestNoSkillsDirectoryIsAnActionableError(t *testing.T) {
	empty := t.TempDir()
	t.Chdir(empty)
	t.Setenv("HOME", empty)

	if _, err := resolveSkillRoots(""); err == nil {
		t.Fatal("expected an error naming where it looked")
	}
}
