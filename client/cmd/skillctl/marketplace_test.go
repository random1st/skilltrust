package main

import (
	"crypto/ed25519"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"gopkg.in/yaml.v3"
)

// signedMarketplace is a marketplace repository signed once, which is where every publisher
// is before their second `marketplace sign`.
func signedMarketplace(t *testing.T) (repository string, key ed25519.PrivateKey) {
	t.Helper()
	home := t.TempDir()
	skilltrustHome := filepath.Join(home, ".skilltrust")
	t.Setenv("SKILLTRUST_HOME", skilltrustHome)
	if err := os.MkdirAll(skilltrustHome, 0o700); err != nil {
		t.Fatal(err)
	}
	signingKey := filepath.Join(skilltrustHome, "signer.key")
	publicKey := filepath.Join(skilltrustHome, "signer.pub")

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Under the sandbox home, because that is where defaultSigningKey resolves to: a key
	// written anywhere else is one the command cannot find.
	if err := attest.WritePrivateKey(signingKey, private); err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePublicKey(publicKey, public); err != nil {
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
		if err := testMarketplaceGit(repository, arguments...); err != nil {
			t.Fatal(err)
		}
	}

	if code := runMarketplaceSign([]string{"--key", signingKey, repository}); code != exitClean {
		t.Fatalf("the first signature = %d", code)
	}
	return repository, private
}

func testMarketplaceGit(repository string, arguments ...string) error {
	command := exec.Command("git", append([]string{
		"-C", repository,
		"-c", "user.email=a@b",
		"-c", "user.name=a",
	}, arguments...)...)
	return command.Run()
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

func TestPrepareNotaryWritesAnOIDCWorkflow(t *testing.T) {
	repository, _ := signedMarketplace(t)

	oldVersion, oldCommit := version, commit
	version, commit = "v1.2.3", "ignored"
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })

	if code := runMarketplacePrepareNotary([]string{"--org", "acme", repository}); code != exitClean {
		t.Fatalf("prepare-notary exit = %d", code)
	}

	body, err := os.ReadFile(filepath.Join(repository, ".github", "workflows", "notarize.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, expected := range []string{
		generatedWorkflowMarker,
		"id-token: write",
		"command: notarize",
		`notary-url: "https://notary.axela.app/v1/catalogs/acme/acme"`,
		"random1st/skilltrust@v1.2.3",
	} {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("workflow is missing %q:\n%s", expected, workflow)
		}
	}
	if strings.Contains(workflow, "notary-token") {
		t.Fatalf("workflow stores a publish token instead of using OIDC:\n%s", workflow)
	}
}

func TestPrepareNotaryUsesTheCommitWhenBuiltFromDev(t *testing.T) {
	repository, _ := signedMarketplace(t)

	oldVersion, oldCommit := version, commit
	version, commit = "dev", "abc123def456"
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })

	if code := runMarketplacePrepareNotary([]string{"--org", "acme", repository}); code != exitClean {
		t.Fatalf("prepare-notary exit = %d", code)
	}
	body, err := os.ReadFile(filepath.Join(repository, ".github", "workflows", "notarize.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "random1st/skilltrust@abc123def456") {
		t.Fatalf("workflow does not pin the build commit:\n%s", string(body))
	}
}

func TestPrepareNotaryRejectsABranchGitCannotUse(t *testing.T) {
	repository, _ := signedMarketplace(t)
	for _, branch := range []string{
		"main\npermissions:\n  id-token: write",
		"refs/heads/main",
		"release..1",
		"feature.lock",
		"/topic",
	} {
		if code := runMarketplacePrepareNotary([]string{
			"--org", "acme",
			"--branch", branch,
			repository,
		}); code != exitUsage {
			t.Fatalf("branch %q exit = %d, want %d", branch, code, exitUsage)
		}
	}
}

func TestPrepareNotaryRejectsAnUnsafeNotaryOrigin(t *testing.T) {
	repository, _ := signedMarketplace(t)
	for _, notary := range []string{
		"https://notary.example.com/path",
		"https://notary.example.com?token=nope",
		"http://notary.example.com",
	} {
		if code := runMarketplacePrepareNotary([]string{
			"--org", "acme",
			"--notary", notary,
			repository,
		}); code != exitUsage {
			t.Fatalf("notary %q exit = %d, want %d", notary, code, exitUsage)
		}
	}
	catalogURL, err := notaryCatalogURL("http://127.0.0.1:8080", "acme", "skills")
	if err != nil {
		t.Fatal(err)
	}
	if catalogURL != "http://127.0.0.1:8080/v1/catalogs/acme/skills" {
		t.Fatalf("catalog URL = %q", catalogURL)
	}
}

func TestMarketplaceWorkflowQuotesDynamicValuesAsStrings(t *testing.T) {
	actionRef := "v1\n  uses: attacker/action@main"
	branch := "on"
	catalogURL := "https://notary.example.com/v1/catalogs/acme/plugins?x=$(nope)\n  notary-url: https://attacker.example"
	workflow := marketplaceWorkflow(actionRef, branch, catalogURL)
	if strings.Contains(workflow, "\n  uses: attacker/action@main") ||
		strings.Contains(workflow, "\n  notary-url: https://attacker.example") {
		t.Fatalf("workflow let dynamic values escape into YAML:\n%s", workflow)
	}

	var document struct {
		On struct {
			Push struct {
				Branches []string `yaml:"branches"`
			} `yaml:"push"`
		} `yaml:"on"`
		Jobs struct {
			Notarize struct {
				Steps []struct {
					Uses string `yaml:"uses"`
					With struct {
						NotaryURL string `yaml:"notary-url"`
					} `yaml:"with"`
				} `yaml:"steps"`
			} `yaml:"notarize"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(workflow), &document); err != nil {
		t.Fatalf("workflow YAML must stay valid: %v\n%s", err, workflow)
	}
	if got := document.On.Push.Branches; len(got) != 1 || got[0] != branch {
		t.Fatalf("branches = %#v, want [%q]", got, branch)
	}
	if got := document.Jobs.Notarize.Steps[1].Uses; got != "random1st/skilltrust@"+actionRef {
		t.Fatalf("uses = %q", got)
	}
	if got := document.Jobs.Notarize.Steps[1].With.NotaryURL; got != catalogURL {
		t.Fatalf("notary-url = %q", got)
	}
}

func TestPrepareNotaryTellsTheUserToReviewCommitAndPush(t *testing.T) {
	repository, _ := signedMarketplace(t)
	output, code := captureStdout(t, func() int {
		return runMarketplacePrepareNotary([]string{"--org", "acme", repository})
	})
	if code != exitClean {
		t.Fatalf("prepare-notary exit = %d", code)
	}
	for _, expected := range []string{
		"Review the diff, then commit",
		"Push that commit to GitHub so GitHub Actions can run.",
		"the first real publish is the first accepted non-empty catalog",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("prepare-notary output is missing %q:\n%s", expected, output)
		}
	}
}

func TestPrepareNotaryRefusesToOverwriteASomeoneWrittenWorkflow(t *testing.T) {
	repository, _ := signedMarketplace(t)
	path := filepath.Join(repository, ".github", "workflows", "notarize.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("name: Custom workflow\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := runMarketplacePrepareNotary([]string{"--org", "acme", repository}); code != exitUsage {
		t.Fatalf("custom workflow overwrite exit = %d", code)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "name: Custom workflow\n" {
		t.Fatalf("custom workflow was overwritten:\n%s", string(body))
	}
}

func TestPrepareNotaryRefreshesItsOwnWorkflowAndBecomesStable(t *testing.T) {
	repository, _ := signedMarketplace(t)

	if code := runMarketplacePrepareNotary([]string{"--org", "acme", repository}); code != exitClean {
		t.Fatalf("prepare-notary exit = %d", code)
	}
	path := filepath.Join(repository, ".github", "workflows", "notarize.yml")
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, append([]byte(generatedWorkflowMarker+"\n"), []byte("name: stale\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runMarketplacePrepareNotary([]string{"--org", "acme", repository}); code != exitClean {
		t.Fatalf("refresh exit = %d", code)
	}
	refreshed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(refreshed) != string(first) {
		t.Fatalf("generated workflow did not refresh back to the canonical content:\n%s", string(refreshed))
	}

	if code := runMarketplacePrepareNotary([]string{"--org", "acme", repository}); code != exitClean {
		t.Fatalf("stable second run exit = %d", code)
	}
	stable, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stable) != string(first) {
		t.Fatalf("up-to-date run rewrote the workflow:\n%s", string(stable))
	}
}

func captureStdout(t *testing.T, run func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = old }()

	code := run()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(body), code
}
