package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/random1st/skilltrust/internal/attest"
)

// The administrator's whole loop: pin a machine's key, see it listed, refuse a silent
// repoint, remove it deliberately. Before `trust` existed this was hand-edited JSON, and
// a hand-edited trust root is how a typo becomes a trust decision.
func TestTrustPinListRemove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	public, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(home, "laptop-roman.pub")
	if err := attest.WritePublicKey(keyFile, public); err != nil {
		t.Fatal(err)
	}

	if code := runTrust([]string{keyFile}); code != exitClean {
		t.Fatalf("pinning exited %d", code)
	}
	pinned, err := attest.PinnedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pinned["laptop-roman"]; !ok {
		t.Fatalf("the file name must become the label; pinned: %v", labelsOf(pinned))
	}

	// A different key under the same label must be refused, not silently repointed —
	// that is how an attacker's key inherits a name everyone already trusts.
	otherPublic, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherFile := filepath.Join(home, "other.pub")
	if err := attest.WritePublicKey(otherFile, otherPublic); err != nil {
		t.Fatal(err)
	}
	if code := runTrust([]string{"--label", "laptop-roman", otherFile}); code == exitClean {
		t.Fatal("repointing a label to a different key must fail")
	}

	if code := runTrust([]string{"--remove", "laptop-roman"}); code != exitClean {
		t.Fatal("removing a pinned label must succeed")
	}
	if code := runTrust([]string{"--remove", "laptop-roman"}); code == exitClean {
		t.Fatal("removing an absent label must be an error, not a no-op")
	}
}

func labelsOf(keys map[string]ed25519.PublicKey) []string {
	labels := make([]string, 0, len(keys))
	for label := range keys {
		labels = append(labels, label)
	}
	return labels
}
