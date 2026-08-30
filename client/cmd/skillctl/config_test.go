package main

import (
	"os"
	"path/filepath"
	"slices"
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

// Every client searches upwards from where it was started towards the repository root, and
// the scanner did not. Anyone who ran a check from inside src/ or server/ — which is where
// people work — was told their machine was clean by a command that never looked at the
// project's own skills one level up.
//
// The clean report is what makes this worth a test rather than a fix: nothing failed, so
// nothing drew attention to it.
func TestSkillRootsAreFoundFromInsideTheProject(t *testing.T) {
	repository := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	projectSkills := filepath.Join(repository, ".agents", "skills")
	if err := os.MkdirAll(projectSkills, 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(repository, "server", "internal", "notary")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	// A home with nothing in it, so anything found came from the climb.
	t.Setenv("HOME", t.TempDir())
	t.Chdir(deep)

	roots, err := resolveSkillRoots("")
	if err != nil {
		t.Fatalf("the project's skills were not found from a subdirectory: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(projectSkills)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(roots, resolved) {
		t.Fatalf("roots = %v, want them to include %s", roots, resolved)
	}
}

// The climb stops at the repository root. Going further would report a sibling checkout's
// skills as this project's — a scanner that over-reports is not more thorough, it is naming
// files the agent will never read and attributing them to the wrong tree.
func TestTheClimbStopsAtTheRepositoryRoot(t *testing.T) {
	outer := t.TempDir()
	// Skills above the repository, belonging to something else entirely.
	stranger := filepath.Join(outer, ".agents", "skills")
	if err := os.MkdirAll(stranger, 0o755); err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(outer, "checkout")
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(repository, ".agents", "skills")
	if err := os.MkdirAll(mine, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())
	t.Chdir(repository)

	roots, err := resolveSkillRoots("")
	if err != nil {
		t.Fatal(err)
	}
	resolvedStranger, err := filepath.EvalSymlinks(stranger)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(roots, resolvedStranger) {
		t.Errorf("the climb went past the repository root and picked up %s", resolvedStranger)
	}
}

// A worktree and a submodule keep a .git file rather than a directory. Testing for a
// directory would turn the climb off for exactly the checkouts people use to work on two
// branches at once.
func TestAWorktreeIsStillARepository(t *testing.T) {
	repository := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(repository, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(repository, "client", "cmd")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	root, found := repositoryRoot(deep)
	if !found {
		t.Fatal("a worktree keeps a .git file, and must still be a repository here")
	}
	resolved, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	gotResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if gotResolved != resolved {
		t.Fatalf("root = %s, want %s", gotResolved, resolved)
	}
}

// Outside a repository the behaviour is what it always was: this directory, and no climb.
// There is no root to stop at, and walking to the filesystem root from a scratch directory
// would report whatever happens to be above it.
func TestWithoutARepositoryOnlyTheWorkingDirectoryIsUsed(t *testing.T) {
	scratch := t.TempDir()
	deep := filepath.Join(scratch, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if bases := workingAncestors(deep); len(bases) != 1 || bases[0] != deep {
		t.Fatalf("bases = %v, want just the working directory", bases)
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
