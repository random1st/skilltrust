package marketplace

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/catalog"
)

// install writes a plugin into the client's cache and returns its digest.
func install(t *testing.T, home, market, plugin, version, body string) string {
	t.Helper()
	dir := InstalledPath(home, market, plugin, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _, err := DigestPlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func snapshotOf(market, plugin, version, digest string) *catalog.Snapshot {
	return &catalog.Snapshot{Name: market, Skills: []catalog.Managed{
		{Name: plugin, Version: version, Digest: digest},
	}}
}

// The property the whole feature rests on: adopting is a claim about exact bytes, not a
// licence to diverge. If it meant "stop checking this plugin", it would be an off switch
// that anything on the machine could reach for, and the protection would be gone for
// precisely the plugins somebody had already chosen to modify.
func TestAdoptionCoversOnlyTheBytesThatWereAdopted(t *testing.T) {
	home := t.TempDir()
	published := "sha256:" + "published"
	mine := install(t, home, "acme", "runbook", "1.0.0", "our staging URL\n")
	snapshot := snapshotOf("acme", "runbook", "1.0.0", published)

	adopted := Adoptions{}.Record(Adoption{
		Marketplace: "acme", Plugin: "runbook",
		From: published, Local: mine, Reason: "our staging URL", Since: time.Now(),
	})

	// The adopted bytes are kept, and reported rather than hidden.
	results := Reconcile(snapshot, Options{ClaudeHome: home, Adopted: adopted, Restore: true})
	if len(results) != 1 || results[0].Outcome != OutcomeAdapted {
		t.Fatalf("the adopted copy must be kept, got %+v", results)
	}
	if results[0].Adapted != "our staging URL" {
		t.Errorf("the reason must survive to the report, got %q", results[0].Adapted)
	}
	if results[0].Outcome.Settled() {
		t.Error("an adapted plugin must not be settled; it has to stay visible")
	}

	// Now somebody edits the file again. That is a different set of bytes from the ones
	// the person approved, so the adoption must stop applying.
	install(t, home, "acme", "runbook", "1.0.0", "our staging URL\nand something else\n")
	results = Reconcile(snapshot, Options{ClaudeHome: home, Adopted: adopted, Restore: false})
	if results[0].Outcome != OutcomeChanged {
		t.Fatalf("an edit after adoption must be a finding again, got %s", results[0].Outcome)
	}
	if results[0].Detail == "" {
		t.Error("the refusal must explain that these are not the adopted bytes")
	}
}

// The other half: the publisher moving on must also end the adoption. Otherwise a machine
// keeps a patched copy of version 1 forever while the catalog has shipped 2, 3 and 4 - and
// nobody is told, because from the machine's side nothing changed.
func TestANewPublishedVersionEndsTheAdoption(t *testing.T) {
	home := t.TempDir()
	mine := install(t, home, "acme", "runbook", "1.0.0", "our staging URL\n")
	adopted := Adoptions{}.Record(Adoption{
		Marketplace: "acme", Plugin: "runbook",
		From: "sha256:the-version-i-patched", Local: mine, Reason: "ours", Since: time.Now(),
	})

	results := Reconcile(snapshotOf("acme", "runbook", "1.0.0", "sha256:something-newer"),
		Options{ClaudeHome: home, Adopted: adopted, Restore: false})
	if results[0].Outcome != OutcomeChanged {
		t.Fatalf("a new published version must end the adoption, got %s", results[0].Outcome)
	}
	if results[0].Detail == "" {
		t.Error("the person must be told their patch is against a version no longer published")
	}
}

// Revocation is a statement about now and outranks a signature. It has to outrank a local
// preference too, or withdrawing a dangerous skill becomes optional on exactly the machines
// that had already decided to keep their own copy of it.
func TestRevocationOutranksAnAdoption(t *testing.T) {
	home := t.TempDir()
	mine := install(t, home, "acme", "runbook", "1.0.0", "mine\n")
	snapshot := snapshotOf("acme", "runbook", "1.0.0", "sha256:published")
	snapshot.Revoked = []catalog.Entry{{Digest: "sha256:published", Reason: "malicious"}}

	adopted := Adoptions{}.Record(Adoption{
		Marketplace: "acme", Plugin: "runbook",
		From: "sha256:published", Local: mine, Reason: "ours", Since: time.Now(),
	})

	results := Reconcile(snapshot, Options{ClaudeHome: home, Adopted: adopted, Restore: true})
	if results[0].Outcome != OutcomeRevoked {
		t.Fatalf("a revoked plugin must stay revoked however it was adopted, got %s",
			results[0].Outcome)
	}
}

// An adoption for one plugin must not quiet another, and a machine with no adoptions must
// behave exactly as every machine did before this existed.
func TestAdoptionIsScopedAndAbsenceChangesNothing(t *testing.T) {
	home := t.TempDir()
	mine := install(t, home, "acme", "runbook", "1.0.0", "mine\n")
	snapshot := snapshotOf("acme", "runbook", "1.0.0", "sha256:published")

	elsewhere := Adoptions{}.Record(Adoption{
		Marketplace: "acme", Plugin: "another-skill",
		From: "sha256:published", Local: mine, Reason: "ours", Since: time.Now(),
	})
	if got := Reconcile(snapshot, Options{ClaudeHome: home, Adopted: elsewhere})[0].Outcome; got != OutcomeChanged {
		t.Errorf("an adoption of a different plugin must not cover this one, got %s", got)
	}
	if got := Reconcile(snapshot, Options{ClaudeHome: home})[0].Outcome; got != OutcomeChanged {
		t.Errorf("with no adoptions the behaviour must be unchanged, got %s", got)
	}
}

// The session hook is the only check most machines ever run. An adoption it does not read
// is an adoption that does not exist: sync would honour it, and then every session would
// quietly put the published bytes back — the exact behaviour this feature was built to end,
// reappearing on the one path nobody watches. This shipped broken until a probe caught it,
// so the property is pinned here rather than left to whoever edits preskill.go next.
func TestEveryRestoringPathMustHonourAdoptions(t *testing.T) {
	home := t.TempDir()
	repository := t.TempDir()
	published := "---\nname: runbook\n---\npublished\n"

	// A checkout to restore from, as the hook has.
	if err := os.MkdirAll(filepath.Join(repository, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(repository, ".claude-plugin", "marketplace.json"),
		[]byte(`{"name":"acme","plugins":[{"name":"runbook","source":"./plugins/runbook","version":"1.0.0"}]}`), 0o644)
	os.MkdirAll(filepath.Join(repository, "plugins", "runbook"), 0o755)
	os.WriteFile(filepath.Join(repository, "plugins", "runbook", "SKILL.md"), []byte(published), 0o644)

	signed, _, err := DigestPlugin(filepath.Join(repository, "plugins", "runbook"))
	if err != nil {
		t.Fatal(err)
	}
	mine := install(t, home, "acme", "runbook", "1.0.0", "---\nname: runbook\n---\nours\n")
	adopted := Adoptions{}.Record(Adoption{
		Marketplace: "acme", Plugin: "runbook",
		From: signed, Local: mine, Reason: "our staging URL", Since: time.Now(),
	})

	// Exactly the options the restoring paths build, with the adoptions passed.
	results := Reconcile(snapshotOf("acme", "runbook", "1.0.0", signed), Options{
		ClaudeHome: home, Adopted: adopted, Restore: true,
		Source: repository, QuarantineRoot: t.TempDir(),
	})
	if results[0].Outcome != OutcomeAdapted {
		t.Fatalf("a restoring path must still honour an adoption, got %s", results[0].Outcome)
	}

	body, err := os.ReadFile(filepath.Join(InstalledPath(home, "acme", "runbook", "1.0.0"), "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == published {
		t.Fatal("the adopted copy was overwritten with the published one")
	}
}
