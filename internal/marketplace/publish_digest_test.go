package marketplace

import (
	"os"
	"path/filepath"
	"testing"
)

// shipped materialises what a clone delivers: the tracked files, and nothing else.
func shipped(t *testing.T, source string, files ...string) string {
	t.Helper()
	destination := t.TempDir()
	for _, name := range files {
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}

// The one invariant the whole scheme rests on: what the publisher signs is what the
// consumer receives.
//
// The publisher digests a working tree full of things git never ships; the consumer
// digests a clone, with no filter at all, because on that side letting the tree decide
// what counts would be the hole. Those two numbers have to be the same number, and nothing
// asserted it before — the filter's own tests only checked that it excluded files, never
// that the result equalled an unfiltered digest of the delivered tree.
func TestAPublishersDigestEqualsWhatAConsumerReceives(t *testing.T) {
	repository := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		target := filepath.Join(repository, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("SKILL.md", "the published instructions\n")
	write("bin/run.sh", "#!/bin/sh\necho hello\n")
	plantRepository(t, repository, "SKILL.md", "bin/run.sh")

	// Everything below is a publisher's local mess: build output git ignores, and a
	// symlink of the kind a package manager leaves behind. None of it reaches a clone.
	write("target/debug/build.log", "compiling\n")
	if err := os.MkdirAll(filepath.Join(repository, "work/scratch/.bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/true", filepath.Join(repository, "work/scratch/.bin/tool")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	published, _, err := DigestPlugin(repository)
	if err != nil {
		t.Fatalf("a working tree with untracked scratch could not be signed: %v", err)
	}
	received, _, err := DigestInstalled(shipped(t, repository, "SKILL.md", "bin/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if published != received {
		t.Fatalf("publisher signed %s but a consumer computes %s; the signature would "+
			"describe a tree that exists on one machine", published, received)
	}
}

// An untracked symlink used to make a whole marketplace unsignable, though not one byte of
// it would have been signed. The entry-type refusals decide what may be *in* an identity,
// so consulting them about bytes that will never be in it is a false refusal, not rigour.
func TestScratchGitNeverShipsCannotVetoASignature(t *testing.T) {
	repository := t.TempDir()
	if err := os.WriteFile(filepath.Join(repository, "SKILL.md"), []byte("instructions\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plantRepository(t, repository, "SKILL.md")

	scratch := filepath.Join(repository, "scratch")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/true", filepath.Join(scratch, "tool")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	if _, _, err := DigestPlugin(repository); err != nil {
		t.Fatalf("an untracked symlink blocked signing: %v", err)
	}

	// The same symlink inside an installed copy is still refused, because there it could
	// decide which bytes the identity covers and there is no git to say it is scratch.
	if _, _, err := DigestInstalled(repository); err == nil {
		t.Fatal("a symlink inside an installed copy was accepted")
	}
}

// Tracking a file deep in a tree must keep the tree walkable. The filter is asked about
// directories before the walk descends, so a set of file paths alone would answer "no" to
// every directory and quietly digest an empty archive — a far worse failure than refusing,
// because it would succeed and sign nothing.
func TestATrackedFileDeepInATreeIsStillReached(t *testing.T) {
	repository := t.TempDir()
	nested := filepath.Join(repository, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "deep.md"), []byte("deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "SKILL.md"), []byte("top\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plantRepository(t, repository, "SKILL.md", "a/b/c/deep.md")

	published, _, err := DigestPlugin(repository)
	if err != nil {
		t.Fatal(err)
	}
	received, _, err := DigestInstalled(shipped(t, repository, "SKILL.md", "a/b/c/deep.md"))
	if err != nil {
		t.Fatal(err)
	}
	if published != received {
		t.Fatalf("a nested tracked file was lost: publisher %s, consumer %s", published, received)
	}
}
