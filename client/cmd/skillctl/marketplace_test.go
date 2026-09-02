package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

// signedMarketplace is a marketplace repository signed once, which is where every publisher
// is before their second `marketplace sign`.
func signedMarketplace(t *testing.T) (repository string, key ed25519.PrivateKey) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", filepath.Join(home, ".skilltrust"))
	if err := os.MkdirAll(os.Getenv("SKILLTRUST_HOME"), 0o700); err != nil {
		t.Fatal(err)
	}

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Under the sandbox home, because that is where defaultSigningKey resolves to: a key
	// written anywhere else is one the command cannot find.
	if err := attest.WritePrivateKey(defaultSigningKey(), private); err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePublicKey(defaultPublicKey(), public); err != nil {
		t.Fatal(err)
	}

	repository = t.TempDir()
	if err := os.MkdirAll(filepath.Join(repository, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repository, ".claude-plugin", "marketplace.json"),
		[]byte(`{"name":"acme","plugins":[{"name":"runbook","source":"./plugins/runbook","version":"1.0.0"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "plugins", "runbook"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repository, "plugins", "runbook", "SKILL.md"),
		[]byte("---\nname: runbook\n---\nfollow it\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Signing digests what git tracks, so the fixture is committed — with an identity on the
	// command line, because the machine running this test may have none.
	for _, arguments := range [][]string{
		{"init", "--quiet", "--initial-branch", "main"},
		{"add", "."},
		{"commit", "--quiet", "-m", "publish"},
	} {
		if err := demoGit(repository, arguments...); err != nil {
			t.Fatal(err)
		}
	}

	if code := runMarketplaceSign([]string{repository}); code != exitClean {
		t.Fatalf("the first signature = %d", code)
	}
	return repository, private
}

// A key that cannot verify the catalog cannot replace it.
//
// This is the property the whole publishing side rests on: the signature beside a
// marketplace says who speaks for it, and a second signer must not be able to take that over
// by running the same command. It had no test, which is how a load-bearing refusal quietly
// becomes optional — so this pins both halves: the command refuses, and the file it refused
// to replace is byte-for-byte what it was.
func TestAKeyThatCannotVerifyTheCatalogCannotReplaceIt(t *testing.T) {
	repository, mine := signedMarketplace(t)
	home := os.Getenv("SKILLTRUST_HOME")

	_, stranger, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	strangerKey := filepath.Join(home, "stranger.key")
	if err := attest.WritePrivateKey(strangerKey, stranger); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(filepath.Join(repository, CatalogFileName))
	if err != nil {
		t.Fatal(err)
	}

	if code := runMarketplaceSign([]string{repository, "--key", strangerKey}); code != exitUsage {
		t.Fatalf("a stranger's key overwrote the catalog; exit = %d", code)
	}

	after, err := os.ReadFile(filepath.Join(repository, CatalogFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the refusal rewrote the file it refused to replace")
	}

	// And the catalog did not advance: a refusal that bumped the sequence would leave every
	// machine that had seen the old one rejecting the next real publish as a rollback.
	envelope, err := attest.LoadEnvelope(filepath.Join(repository, CatalogFileName))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := catalog.Open(envelope,
		attest.NewTrustedKeys(mine.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Sequence != 1 {
		t.Errorf("sequence = %d, want 1: the catalog must not move under a refusal", snapshot.Sequence)
	}
}
