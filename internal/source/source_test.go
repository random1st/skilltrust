package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFetchContextClonesAFullHeadRefAndKeepsItsPin(t *testing.T) {
	repository := createRepository(t)
	firstCommit := commitFile(t, repository, "README.md", "first\n")

	root := t.TempDir()
	fetched, err := FetchContext(context.Background(), root, "catalog", repository, "refs/heads/main")
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if fetched.Ref != "refs/heads/main" {
		t.Fatalf("ref = %q, want full hosted ref", fetched.Ref)
	}
	if fetched.Commit != firstCommit {
		t.Fatalf("commit = %q, want %q", fetched.Commit, firstCommit)
	}
	if branch, err := run(Path(root, "catalog"), "symbolic-ref", "--short", "HEAD"); err != nil || branch != "main" {
		t.Fatalf("checked out branch = %q, %v; want main", branch, err)
	}

	secondCommit := commitFile(t, repository, "README.md", "second\n")
	refreshed, err := FetchContext(context.Background(), root, "catalog", repository, "refs/heads/main")
	if err != nil {
		t.Fatalf("refresh fetch: %v", err)
	}
	if refreshed.Ref != "refs/heads/main" {
		t.Fatalf("ref after refresh = %q, want full hosted ref", refreshed.Ref)
	}
	if refreshed.Commit != secondCommit {
		t.Fatalf("commit after refresh = %q, want %q", refreshed.Commit, secondCommit)
	}
}

func TestCloneContextStopsPromptlyAfterDeadlineEvenIfGitLeavesAChildHoldingThePipes(t *testing.T) {
	withFakeGit(t, `#!/bin/sh
case "$1" in
clone)
	(sleep 1) &
	sleep 5
	;;
*)
	exit 0
	;;
esac
`, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()

		start := time.Now()
		err := cloneContext(ctx, filepath.Join(t.TempDir(), "checkout"), "https://example.com/repo.git", "main")
		elapsed := time.Since(start)

		if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("clone error = %v, want context deadline exceeded", err)
		}
		if elapsed >= 900*time.Millisecond {
			t.Fatalf("clone took %v after deadline; descendant pipes were not bounded", elapsed)
		}
	})
}

func TestRunContextStopsPromptlyAfterDeadlineEvenIfGitLeavesAChildHoldingThePipes(t *testing.T) {
	withFakeGit(t, `#!/bin/sh
if [ "$1" = "-C" ]; then
	shift 2
fi
case "$1" in
rev-parse)
	(sleep 1) &
	sleep 5
	;;
*)
	exit 0
	;;
esac
`, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := runContext(ctx, t.TempDir(), "rev-parse", "HEAD")
		elapsed := time.Since(start)

		if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("run error = %v, want context deadline exceeded", err)
		}
		if elapsed >= 900*time.Millisecond {
			t.Fatalf("run took %v after deadline; descendant pipes were not bounded", elapsed)
		}
	})
}

func createRepository(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	gitExec(t, "", "init", "--quiet", "-b", "main", repository)
	gitExec(t, repository, "config", "user.email", "tests@example.com")
	gitExec(t, repository, "config", "user.name", "tests")
	return repository
}

func commitFile(t *testing.T, repository, name, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repository, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, repository, "add", name)
	gitExec(t, repository, "commit", "--quiet", "-m", body)
	return gitOutput(t, repository, "rev-parse", "HEAD")
}

func gitExec(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	if directory != "" {
		command.Dir = directory
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
}

func gitOutput(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

func withFakeGit(t *testing.T, script string, run func()) {
	t.Helper()
	bin := t.TempDir()
	path := filepath.Join(bin, "git")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	run()
}
