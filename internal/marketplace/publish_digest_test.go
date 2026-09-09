package marketplace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shipped is what a consumer actually receives: a real clone.
//
// An earlier version of this copied a hand-listed set of files and wrote each one 0644.
// That quietly assumed the thing under test — the list was written by hand, so it could
// never have caught a file the publisher's filter dropped — and it erased the executable
// bit, which is part of the identity by design. Cloning asks git the question instead of
// answering it on git's behalf.
func shipped(t *testing.T, source string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "clone")
	clone := exec.Command("git", "clone", "--quiet", source, destination)
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, output)
	}
	return destination
}

func writeFile(t *testing.T, root, name, body string, mode os.FileMode) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// The one invariant the whole scheme rests on: what the publisher signs is what the
// consumer receives.
//
// The publisher digests a working tree full of things git never ships; the consumer digests
// a clone, with no filter at all, because on that side letting the tree decide what counts
// would be the hole. Those two numbers have to be the same number, and nothing asserted it
// before — the filter's own tests only checked that it excluded files.
//
// The executable bit is deliberately in the fixture. It is part of the identity, so a
// helper that flattened every mode to 0644 would have compared two trees that agreed only
// because the test made them agree.
func TestAPublishersDigestEqualsWhatAConsumerReceives(t *testing.T) {
	repository := t.TempDir()
	writeFile(t, repository, "SKILL.md", "the published instructions\n", 0o644)
	writeFile(t, repository, "bin/run.sh", "#!/bin/sh\necho hello\n", 0o755)
	writeFile(t, repository, "docs/nested/deep.md", "deep\n", 0o644)
	plantRepository(t, repository, "SKILL.md", "bin/run.sh", "docs/nested/deep.md")

	// A publisher's local mess: build output git ignores, and a symlink of the kind a
	// package manager leaves behind. None of it reaches a clone.
	writeFile(t, repository, "target/debug/build.log", "compiling\n", 0o644)
	if err := os.MkdirAll(filepath.Join(repository, "work/scratch"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/true", filepath.Join(repository, "work/scratch/tool")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	published, _, err := DigestPlugin(repository)
	if err != nil {
		t.Fatalf("a working tree with untracked scratch could not be signed: %v", err)
	}
	clone := shipped(t, repository)
	received, _, err := DigestInstalled(clone)
	if err != nil {
		t.Fatal(err)
	}
	if published != received {
		t.Fatalf("publisher signed %s but a consumer computes %s; the signature would "+
			"describe a tree that exists on one machine", published, received)
	}

	// Guard the guard: if the clone lost the executable bit, the comparison above would
	// still pass and would be proving nothing about modes.
	info, err := os.Stat(filepath.Join(clone, "bin", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("the clone dropped the executable bit, so this test no longer covers modes")
	}
}

// An untracked symlink used to make a whole marketplace unsignable, though not one byte of
// it would have been signed. The entry-type refusals decide what may be *in* an identity,
// so consulting them about bytes that will never be in it is a false refusal, not rigour.
func TestScratchGitNeverShipsCannotVetoASignature(t *testing.T) {
	repository := t.TempDir()
	writeFile(t, repository, "SKILL.md", "instructions\n", 0o644)
	plantRepository(t, repository, "SKILL.md")

	if err := os.MkdirAll(filepath.Join(repository, "scratch"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/true", filepath.Join(repository, "scratch/tool")); err != nil {
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

// A file git tracks but the working tree no longer has is the quietest way to sign a digest
// nobody can reproduce: the walk sees only disk, so the file simply is not there, while a
// clone hands the consumer every byte of it. Every install would then read as tampering,
// and the publisher would have had no warning at all.
func TestSigningRefusesWhenATrackedFileIsMissingFromDisk(t *testing.T) {
	repository := t.TempDir()
	writeFile(t, repository, "SKILL.md", "instructions\n", 0o644)
	writeFile(t, repository, "docs/guide.md", "guide\n", 0o644)
	plantRepository(t, repository, "SKILL.md", "docs/guide.md")

	if _, _, err := DigestPlugin(repository); err != nil {
		t.Fatalf("a complete working tree was refused: %v", err)
	}

	if err := os.Remove(filepath.Join(repository, "docs", "guide.md")); err != nil {
		t.Fatal(err)
	}
	_, _, err := DigestPlugin(repository)
	if err == nil {
		t.Fatal("signed a tree missing a file that a clone delivers")
	}
	// The publisher has to be able to act on this, so it has to name the file.
	if !strings.Contains(err.Error(), "docs/guide.md") {
		t.Fatalf("the refusal does not name what is missing: %v", err)
	}
}

// A submodule is tracked as a pointer, never as contents, so nothing under one is inside
// the signature — while a recursive clone still delivers those bytes. That is a decision
// for the publisher rather than a refusal, and it is worthless unless they are told where.
func TestASubmodulesContentsAreReportedAsOutsideTheSignature(t *testing.T) {
	inner := t.TempDir()
	writeFile(t, inner, "lib.sh", "inner payload\n", 0o755)
	plantRepository(t, inner, "lib.sh")

	repository := t.TempDir()
	writeFile(t, repository, "SKILL.md", "instructions\n", 0o644)
	plantRepository(t, repository, "SKILL.md")
	add := exec.Command("git", "-C", repository, "-c", "protocol.file.allow=always",
		"-c", "user.email=a@b", "-c", "user.name=a",
		"submodule", "add", "--quiet", inner, "vendor")
	if output, err := add.CombinedOutput(); err != nil {
		t.Skipf("this git will not add a local submodule: %v\n%s", err, output)
	}

	digest, submodules, _, err := digestPublished(repository)
	if err != nil {
		t.Fatalf("a repository with a submodule could not be signed: %v", err)
	}
	if len(submodules) != 1 || submodules[0] != "vendor" {
		t.Fatalf("submodules = %v, want exactly the vendor pointer", submodules)
	}

	// And the claim is true, not just announced: changing the submodule's contents must
	// leave the digest alone, which is precisely why it has to be said out loud.
	writeFile(t, repository, "vendor/lib.sh", "different payload\n", 0o755)
	again, _, _, err := digestPublished(repository)
	if err != nil {
		t.Fatal(err)
	}
	if again != digest {
		t.Fatal("the submodule's contents turned out to be inside the signature after all")
	}
}
