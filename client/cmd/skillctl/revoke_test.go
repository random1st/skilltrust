package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

// Revoking one skill must not unmanage the rest.
//
// Found by revoking a plugin in a marketplace catalog and watching every subscribed
// machine report "0 signed plugins": extending the catalog carried the sequence and the
// revocations across but dropped the name and the skill list, so the next catalog named
// nothing. That is the worst shape a failure can take here — the machines do not refuse
// anything, they quietly stop managing skills they were managing a moment ago, and the
// advanced sequence means the previous good catalog can no longer be republished.
func TestRevokingKeepsTheSkillsTheCatalogNames(t *testing.T) {
	home := t.TempDir()
	catalogPath := filepath.Join(home, "catalog.dsse.json")
	keyPath := filepath.Join(home, "signer.key")
	trustedPath := filepath.Join(home, "trusted-keys.json")

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(keyPath, private); err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(trustedPath, "publisher", public); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	original := catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: "acme", Sequence: 1,
		IssuedAt: now, ValidUntil: now.Add(7 * 24 * time.Hour),
		Skills: []catalog.Managed{
			{Name: "deploy-runbook", Digest: "sha256:aaa", Version: "1.0.0"},
			{Name: "incident-drill", Digest: "sha256:bbb", Version: "2.0.0"},
		},
	}
	envelope, err := catalog.Sign(original, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Save(catalogPath); err != nil {
		t.Fatal(err)
	}

	if code := runCatalogRevoke([]string{
		"-catalog", catalogPath, "-key", keyPath, "-trusted-keys", trustedPath,
		"-reason", "prompt injection", "sha256:aaa",
	}); code != exitClean {
		t.Fatalf("revoke exited %d", code)
	}

	revoked, err := attest.LoadEnvelope(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	updated, _, err := catalog.Open(revoked, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}

	if updated.Sequence != 2 {
		t.Fatalf("sequence %d, want 2", updated.Sequence)
	}
	if len(updated.Revoked) != 1 || updated.Revoked[0].Digest != "sha256:aaa" {
		t.Fatalf("revocations = %+v", updated.Revoked)
	}
	// The name identifies the marketplace to every machine that follows it.
	if updated.Name != "acme" {
		t.Fatalf("name = %q, want acme — an unnamed catalog manages nobody's marketplace", updated.Name)
	}
	if len(updated.Skills) != len(original.Skills) {
		t.Fatalf("the catalog names %d skills after revoking one of them, want %d",
			len(updated.Skills), len(original.Skills))
	}
	// Revocation is by digest and deliberately independent of the listing: a revoked
	// skill stays named so a machine still holding it recognises what it has, and refuses
	// it for being revoked rather than ignoring it for being unmanaged.
	found := map[string]bool{}
	for _, skill := range updated.Skills {
		found[skill.Digest] = true
	}
	if !found["sha256:aaa"] || !found["sha256:bbb"] {
		t.Fatalf("skills after revoking = %+v", updated.Skills)
	}
}

// Revoking with no catalog yet is a standalone revocation list: there is nothing to
// preserve, and it must not invent a marketplace name.
func TestRevokingWithoutAnExistingCatalogStartsFresh(t *testing.T) {
	home := t.TempDir()
	catalogPath := filepath.Join(home, "catalog.dsse.json")
	keyPath := filepath.Join(home, "signer.key")

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(keyPath, private); err != nil {
		t.Fatal(err)
	}

	if code := runCatalogRevoke([]string{
		"-catalog", catalogPath, "-key", keyPath,
		"-trusted-keys", filepath.Join(home, "absent.json"), "sha256:ccc",
	}); code != exitClean {
		t.Fatalf("revoke exited %d", code)
	}
	if _, err := os.Stat(catalogPath); err != nil {
		t.Fatal(err)
	}

	envelope, err := attest.LoadEnvelope(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := catalog.Open(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Sequence != 1 || len(snapshot.Revoked) != 1 || len(snapshot.Skills) != 0 {
		t.Fatalf("a fresh revocation catalog = %+v", snapshot)
	}
}
