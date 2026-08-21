package archive

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// goldenDigest pins the canonical identity of the fixture tree below.
//
// The digest is the product. If a refactor, a Go release, or a platform difference changes
// it, every previously notarized artifact becomes unverifiable — so this constant must only
// ever change together with a documented format version bump.
const goldenDigest = "sha256:664331d6eb71c46d5ed5c8627ef0dd247c412693c9f68a3079cf8b5e15208ea8"

// buildFixture materialises the tree the golden digest was computed from.
func buildFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "SKILL.md", "---\nname: demo\ndescription: A demo skill.\n---\n\nBody.\n", 0o644)
	write(t, root, "references/REFERENCE.md", "Reference text.\n", 0o644)
	write(t, root, "scripts/run.sh", "#!/bin/sh\necho hi\n", 0o755)
	return root
}

func write(t *testing.T, root, relative, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenDigestIsStable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture depends on the executable bit, which Windows does not carry")
	}

	result, err := Build(buildFixture(t), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Digest != goldenDigest {
		t.Fatalf("canonical format changed\n  want %s\n  got  %s", goldenDigest, result.Digest)
	}
	if len(result.Files) != 3 {
		t.Fatalf("files = %d", len(result.Files))
	}
	if !result.Files[2].Executable {
		t.Fatalf("scripts/run.sh must be recorded as executable: %+v", result.Files[2])
	}
}

func TestDigestIsIndependentOfTimestampsAndOwnership(t *testing.T) {
	first := buildFixture(t)
	second := buildFixture(t)

	// A tree packaged a moment later, from a different directory, must be identical.
	future := os.Chtimes(filepath.Join(second, "SKILL.md"),
		zeroTime.AddDate(30, 0, 0), zeroTime.AddDate(30, 0, 0))
	if future != nil {
		t.Fatal(future)
	}

	a, err := Build(first, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(second, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("digest depends on mtime or path: %s != %s", a.Digest, b.Digest)
	}
}

func TestExecutableBitChangesTheDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no executable bit; see TestExecutableBitIsAbsentOnWindows")
	}
	root := buildFixture(t)
	before, err := Build(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(filepath.Join(root, "scripts", "run.sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := Build(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if before.Digest == after.Digest {
		t.Fatal("dropping the executable bit must change the identity")
	}
}

func TestUnsafeTreesAreRejected(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := buildFixture(t)
		if err := os.Symlink("/etc/passwd", filepath.Join(root, "link")); err != nil {
			t.Skipf("cannot create symlinks here: %v", err)
		}
		assertKind(t, root, KindEntryType)
	})

	t.Run("file count limit", func(t *testing.T) {
		root := t.TempDir()
		for index := range 5 {
			write(t, root, filepath.Join("f", string(rune('a'+index))+".md"), "x", 0o644)
		}
		if _, err := Build(root, Limits{MaxFiles: 3}); err == nil {
			t.Fatal("expected a limit error")
		} else if packaging, ok := err.(*Error); !ok || packaging.Kind != KindLimit {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("per-file size limit", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "big.md", "0123456789", 0o644)
		if _, err := Build(root, Limits{MaxFileBytes: 4}); err == nil {
			t.Fatal("expected a limit error")
		}
	})
}

func assertKind(t *testing.T, root string, want Kind) {
	t.Helper()
	_, err := Build(root, Limits{})
	if err == nil {
		t.Fatalf("expected a %s error", want)
	}
	packaging, ok := err.(*Error)
	if !ok || packaging.Kind != want {
		t.Fatalf("err = %v, want kind %s", err, want)
	}
}

func TestCanonicalMemberPath(t *testing.T) {
	rejected := []string{"", "/absolute", "a/../b", "./a", "a//b", `a\b`, "a/\x00b"}
	for _, candidate := range rejected {
		if _, err := canonicalMemberPath(candidate); err == nil {
			t.Fatalf("path %q must be rejected", candidate)
		}
	}

	// macOS stores this decomposed and Linux composed; both must canonicalize alike.
	composed, err := canonicalMemberPath("café/notes.md")
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := canonicalMemberPath("café/notes.md")
	if err != nil {
		t.Fatal(err)
	}
	if composed != decomposed {
		t.Fatalf("NFC normalization failed: %q != %q", composed, decomposed)
	}
}

// Collision detection is tested against the registry rather than the filesystem: a
// case-insensitive volume such as APFS silently merges the two names, so the filesystem
// cannot express the case this rule exists to catch.
func TestRegistryRejectsAmbiguousTrees(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*pathRegistry) error
	}{
		{
			name: "paths differing only by case",
			prepare: func(r *pathRegistry) error {
				if err := r.registerFile("notes/One.md"); err != nil {
					return err
				}
				return r.registerFile("notes/one.md")
			},
		},
		{
			name: "paths differing only by Unicode form",
			prepare: func(r *pathRegistry) error {
				if err := r.registerFile("caf\u00e9.md"); err != nil {
					return err
				}
				return r.registerFile("cafe\u0301.md")
			},
		},
		{
			name: "directory nested under a regular file",
			prepare: func(r *pathRegistry) error {
				if err := r.registerFile("notes"); err != nil {
					return err
				}
				return r.registerFile("notes/inner.md")
			},
		},
		{
			name: "duplicate file",
			prepare: func(r *pathRegistry) error {
				if err := r.registerFile("a.md"); err != nil {
					return err
				}
				return r.registerFile("a.md")
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.prepare(newPathRegistry())
			if err == nil {
				t.Fatal("expected a collision error")
			}
			packaging, ok := err.(*Error)
			if !ok || packaging.Kind != KindCollision {
				t.Fatalf("err = %v, want a collision", err)
			}
		})
	}
}

// Registering the same directory twice is legitimate: two files share a parent.
func TestRegistryAllowsRepeatedDirectories(t *testing.T) {
	registry := newPathRegistry()
	if err := registry.registerFile("notes/a.md"); err != nil {
		t.Fatal(err)
	}
	if err := registry.registerFile("notes/b.md"); err != nil {
		t.Fatal(err)
	}
}

// Pins the platform gap so it is a known, tested property rather than a surprise: a tree
// containing executables does not produce the same digest on Windows as on POSIX.
func TestExecutableBitIsAbsentOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("describes Windows behaviour")
	}

	result, err := Build(buildFixture(t), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range result.Files {
		if file.Executable {
			t.Fatalf("%s reports an executable bit Windows cannot store", file.Path)
		}
	}
	if result.Digest == goldenDigest {
		t.Fatal("if Windows ever matches the POSIX digest, the limitation is gone and " +
			"this test plus the skips that reference it should go with it")
	}
}
