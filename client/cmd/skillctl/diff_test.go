package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
)

type recoveryFixture struct {
	home, installed, source string
	subscription            Subscription
	snapshot                catalog.Snapshot
	key                     ed25519.PrivateKey
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", filepath.Join(root, "state ' $() ; &"))
	home := filepath.Join(root, "client ' $(touch SHOULD_NOT_EXIST) ; &")
	installed := marketplace.InstalledPath(home, "acme", "runbook", "1.0.0")
	source := filepath.Join(root, "source")
	writeQuarantineSkill(t, source, "published\n")
	writeQuarantineSkill(t, installed, "published\n")
	digest, _, err := marketplace.DigestInstalled(installed)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := attest.SaveTrustedKeys(defaultTrustedKeys(), map[string]ed25519.PublicKey{"fixture": public}); err != nil {
		t.Fatal(err)
	}
	subscription := Subscription{Name: "acme", Repository: "/unused/offline", KeyIDs: []string{attest.KeyID(public)}}
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}
	snapshot := catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: "acme", Sequence: 1,
		IssuedAt: time.Now().UTC().Add(-time.Minute), ValidUntil: time.Now().UTC().Add(time.Hour),
		Skills: []catalog.Managed{{Name: "runbook", Version: "1.0.0", Digest: digest}},
	}
	writeCatalogIndex(t, subscription, snapshot, key)
	return recoveryFixture{home, installed, source, subscription, snapshot, key}
}

func (f recoveryFixture) keep(t *testing.T, body string, when time.Time) (string, string) {
	t.Helper()
	writeQuarantineSkill(t, f.installed, body)
	digest, _, err := marketplace.DigestInstalled(f.installed)
	if err != nil {
		t.Fatal(err)
	}
	path, err := marketplace.Restore(f.installed, f.source, quarantineRoot(), "runbook", when)
	if err != nil {
		t.Fatal(err)
	}
	return path, digest
}

// A second check can save another edit after the person inspected the first one. The
// command for their reviewed copy must not run the newest selector again at adoption.
func TestAdoptExactQuarantineRecoversReviewedCopy(t *testing.T) {
	f := newRecoveryFixture(t)
	now := time.Now().UTC()
	reviewed, digest := f.keep(t, "reviewed first edit\n", now)
	later, _ := f.keep(t, "later unreviewed edit\n", now.Add(time.Second))
	if newest, _, err := marketplace.NewestQuarantine(quarantineRoot(), f.installed, "runbook"); err != nil || newest != later {
		t.Fatalf("fixture must make latest selection differ from reviewed: %q, %v", newest, err)
	}
	code := runAdopt([]string{"runbook", "--marketplace", "acme", "--claude-home", f.home,
		"--quarantine", reviewed, "--quarantine-digest", digest, "--because", "reviewed our local endpoint"})
	if code != exitClean {
		t.Fatalf("adopting the exact reviewed copy: exit %d", code)
	}
	assertQuarantineSkill(t, f.installed, "reviewed first edit\n")
	assertQuarantineSkill(t, later, "later unreviewed edit\n")
	adoptions, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := adoptions.Find("acme", "runbook")
	if !ok || entry.Local != digest || entry.Reason != "reviewed our local endpoint" {
		t.Fatalf("recorded different bytes or reason: %+v", entry)
	}
}

func TestDiffShowsOnlySkillPayloadWithoutChangingState(t *testing.T) {
	f := newRecoveryFixture(t)
	saved, _ := f.keep(t, "reviewed edit\n", time.Now())
	for _, name := range marketplace.ClientManagedRoots {
		writeQuarantineSkill(t, filepath.Join(saved, name), "DO_NOT_SHOW_SAVED_CLIENT_DATA\n")
		writeQuarantineSkill(t, filepath.Join(f.installed, name), "DO_NOT_SHOW_CURRENT_CLIENT_DATA\n")
	}
	for _, name := range []string{"catalog.dsse.json", "ATTESTATION.dsse.json"} {
		if err := os.WriteFile(filepath.Join(saved, name), []byte("DO_NOT_SHOW_SIGNATURE_METADATA"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(saved, ".local-note"), []byte("hidden local payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	trustedBefore, err := os.ReadFile(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	var code int
	output := capture(t, func() {
		code = runDiff([]string{"runbook", "--marketplace", "acme", "--claude-home", f.home, "--quarantine", saved})
	})
	for _, want := range []string{"-published", "+reviewed edit", ".local-note", "+hidden local payload", "--quarantine-digest"} {
		if !strings.Contains(output, want) {
			t.Fatalf("diff did not show %q: %s", want, output)
		}
	}
	if code != exitFindings || strings.Contains(output, "DO_NOT_SHOW") {
		t.Fatalf("diff exposed metadata or hid payload changes: exit %d, %s", code, output)
	}
	assertQuarantineSkill(t, f.installed, "published\n")
	assertQuarantineSkill(t, saved, "reviewed edit\n")
	trustedAfter, err := os.ReadFile(defaultTrustedKeys())
	if err != nil || !bytes.Equal(trustedBefore, trustedAfter) {
		t.Fatalf("read-only review changed trust: %v", err)
	}
	for _, path := range []string{defaultSigningKey(), defaultAdoptions(), snapshotStatePath(f.subscription)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("read-only review wrote %q: %v", path, err)
		}
	}
}

func TestDiffIgnoresOnlyExcludedChanges(t *testing.T) {
	f := newRecoveryFixture(t)
	saved, _ := f.keep(t, "published\n", time.Now())
	writeQuarantineSkill(t, filepath.Join(saved, "node_modules"), "old dependency\n")
	writeQuarantineSkill(t, filepath.Join(f.installed, "node_modules"), "new dependency\n")
	var code int
	output := capture(t, func() { code = runDiff([]string{"runbook", "--claude-home", f.home, "--quarantine", saved}) })
	if code != exitClean || !strings.Contains(output, "No skill payload changes") || strings.Contains(output, "Run:") {
		t.Fatalf("client-owned changes were offered for adoption: exit %d, %s", code, output)
	}
}

func TestPayloadDiffReportsBinaryModeAndEmptyFileChanges(t *testing.T) {
	before, after := t.TempDir(), t.TempDir()
	for _, directory := range []string{before, after} {
		if err := os.WriteFile(filepath.Join(directory, "run.sh"), []byte("echo reviewed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(after, "run.sh"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for directory, body := range map[string][]byte{before: {0, 1}, after: {0, 2}} {
		if err := os.WriteFile(filepath.Join(directory, "data.bin"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for directory, name := range map[string]string{before: "removed", after: ".new-empty"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	left, err := marketplace.InstalledPayload(before)
	if err != nil {
		t.Fatal(err)
	}
	right, err := marketplace.InstalledPayload(after)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	changed, err := writePayloadDiff(&out, left, right)
	if err != nil || !changed {
		t.Fatalf("different binary/mode/empty files looked identical: %v, %s", err, out.String())
	}
	for _, want := range []string{"Binary contents differ", "sha256:", ".new-empty", "removed", "/dev/null"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("diff hid %q: %s", want, out.String())
		}
	}
	if runtime.GOOS != "windows" && !strings.Contains(out.String(), "mode 0644 -> 0755") {
		t.Fatalf("executable permission change was hidden: %s", out.String())
	}
}

func TestAdoptExactQuarantineRequiresReviewAndRejectsRevokedBytes(t *testing.T) {
	for _, refusal := range []string{"no digest", "changed saved", "changed installed", "revoked saved", "other client"} {
		t.Run(refusal, func(t *testing.T) {
			f := newRecoveryFixture(t)
			saved, digest := f.keep(t, "reviewed edit\n", time.Now())
			wantedInstalled, wantedSaved := "published\n", "reviewed edit\n"
			home := f.home
			switch refusal {
			case "no digest":
				digest = ""
			case "changed saved":
				wantedSaved = "unreviewed replacement\n"
				writeQuarantineSkill(t, saved, wantedSaved)
			case "changed installed":
				wantedInstalled = "fresh local work\n"
				writeQuarantineSkill(t, f.installed, wantedInstalled)
			case "revoked saved":
				f.snapshot.Sequence++
				f.snapshot.Revoked = []catalog.Entry{{Digest: digest, Reason: "withdrawn local payload"}}
				writeCatalogIndex(t, f.subscription, f.snapshot, f.key)
			case "other client":
				home = t.TempDir()
				writeQuarantineSkill(t, marketplace.InstalledPath(home, "acme", "runbook", "1.0.0"), "published\n")
			}
			args := []string{"runbook", "--claude-home", home, "--quarantine", saved, "--because", "reviewed"}
			if digest != "" {
				args = append(args, "--quarantine-digest", digest)
			}
			var code int
			output := capture(t, func() { code = runAdopt(args) })
			if code == exitClean {
				t.Fatal("recovery accepted a copy without this review and target")
			}
			if refusal == "no digest" && (!strings.Contains(output, "Run: skillctl diff") || !strings.Contains(output, "--quarantine")) {
				t.Fatalf("missing digest did not give an exact review command: %s", output)
			}
			assertQuarantineSkill(t, f.installed, wantedInstalled)
			assertQuarantineSkill(t, saved, wantedSaved)
			if _, err := os.Lstat(defaultAdoptions()); !os.IsNotExist(err) {
				t.Fatalf("failed recovery recorded an adoption: %v", err)
			}
			if refusal == "revoked saved" {
				output = capture(t, func() { runDiff([]string{"runbook", "--claude-home", home, "--quarantine", saved}) })
				if !strings.Contains(output, "revoked") || strings.Contains(output, "Run:") {
					t.Fatalf("review offered a command for revoked bytes: %s", output)
				}
			}
			if refusal == "changed installed" || refusal == "revoked saved" {
				capture(t, func() {
					code = runAdopt([]string{"runbook", "--claude-home", home, "--from-quarantine", "--because", "legacy intentional recovery"})
				})
				if code == exitClean {
					t.Fatal("legacy selector bypassed the same recovery preflight")
				}
				assertQuarantineSkill(t, f.installed, wantedInstalled)
				assertQuarantineSkill(t, saved, wantedSaved)
			}
		})
	}
}

func TestDiffEscapesControlCharactersAndCommandsRequireKnownHome(t *testing.T) {
	f := newRecoveryFixture(t)
	f.home = filepath.Join(t.TempDir(), "client\n\x1b[31m")
	f.installed = marketplace.InstalledPath(f.home, "acme", "runbook", "1.0.0")
	writeQuarantineSkill(t, f.installed, "published\n")
	saved, _ := f.keep(t, "reviewed\n", time.Now())
	output := capture(t, func() { runDiff([]string{"runbook", "--claude-home", f.home, "--quarantine", saved}) })
	if strings.Contains(output, "\x1b") || !strings.Contains(output, "Next command arguments (escaped):") {
		t.Fatalf("control characters reached the terminal or an unsafe copy/paste command: %q", output)
	}
	for _, home := range []string{"", "relative/home"} {
		diff, adopt := quarantineCommands(marketplace.Result{Plugin: "runbook", Marketplace: "acme", ClientHome: home}, saved, "digest", "reason")
		if diff != nil || adopt != nil {
			t.Fatalf("missing exact client home guessed a recovery target: %v, %v", diff, adopt)
		}
	}
}

func TestRecoveryCLIProcess(t *testing.T) {
	if os.Getenv("AXELA_RECOVERY_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"skillctl"}, os.Args[i+1:]...)
			main()
			t.Fatal("main returned without exit status")
		}
	}
	t.Fatal("missing command arguments")
}

func TestDiffPrintedCommandKeepsReviewedCopyAfterAnotherRestore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("terminal commands use POSIX shell quoting")
	}
	f := newRecoveryFixture(t)
	now := time.Now()
	reviewed, reviewedDigest := f.keep(t, "first reviewed edit\n", now)
	output := capture(t, func() { runDiff([]string{"runbook", "--claude-home", f.home, "--quarantine", reviewed}) })
	var command string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Run: ") {
			command = strings.TrimPrefix(line, "Run: ")
		}
	}
	if command == "" || !strings.Contains(command, reviewedDigest) {
		t.Fatalf("review produced no payload-bound command: %s", output)
	}
	later, _ := f.keep(t, "second unreviewed edit\n", now.Add(time.Second))
	writeQuarantineSkill(t, filepath.Join(f.installed, ".in_use"), "new live session\n")
	bin := t.TempDir()
	wrapper := "#!/bin/sh\nexec \"$AXELA_RECOVERY_TEST_BIN\" -test.run=^TestRecoveryCLIProcess$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "skillctl"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Dir = bin
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AXELA_RECOVERY_TEST_PROCESS=1", "AXELA_RECOVERY_TEST_BIN="+self)
	if body, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("printed command failed: %v\n%s", err, body)
	}
	assertQuarantineSkill(t, f.installed, "first reviewed edit\n")
	assertQuarantineSkill(t, later, "second unreviewed edit\n")
	assertQuarantineSkill(t, filepath.Join(f.installed, ".in_use"), "new live session\n")
	if _, err := os.Lstat(filepath.Join(bin, "SHOULD_NOT_EXIST")); !os.IsNotExist(err) {
		t.Fatalf("path metacharacters executed as shell code: %v", err)
	}
}
