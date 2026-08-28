package pluginid

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, name, body string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// The point of exporting this is that a second party gets the same answer from the same
// bytes — including from a copy made somewhere else entirely, which is what a hosted
// verifier has: an archive it extracted, not the publisher's working tree.
func TestTheSameBytesGiveTheSameDigestWhereverTheyAre(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, root := range []string{first, second} {
		write(t, root, "SKILL.md", "---\nname: demo\n---\nDo the thing.\n", 0o644)
		write(t, root, "scripts/run.sh", "#!/bin/sh\necho hi\n", 0o755)
	}

	a, _, err := Of(first)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Of(second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a == "" {
		t.Fatalf("two copies of the same tree must share an identity: %q vs %q", a, b)
	}
}

// The executable bit is part of the identity, because it is part of what the bytes do. A
// verifier that reconstructs a tree without it computes a different digest and reports a
// faithful copy as tampered — which is why anything materialising a tree to check it must
// carry the mode through.
func TestTheExecutableBitChangesTheIdentity(t *testing.T) {
	plain, runnable := t.TempDir(), t.TempDir()
	write(t, plain, "SKILL.md", "x\n", 0o644)
	write(t, plain, "run.sh", "#!/bin/sh\n", 0o644)
	write(t, runnable, "SKILL.md", "x\n", 0o644)
	write(t, runnable, "run.sh", "#!/bin/sh\n", 0o755)

	a, _, err := Of(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Of(runnable)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("a file that can run and one that cannot must not share an identity")
	}
}
