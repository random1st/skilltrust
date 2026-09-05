package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
)

// capture runs f with stdout redirected and returns what it printed.
func capture(t *testing.T, f func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	done := make(chan string, 1)
	go func() {
		var builder strings.Builder
		buffer := make([]byte, 4096)
		for {
			n, err := read.Read(buffer)
			if n > 0 {
				builder.Write(buffer[:n])
			}
			if err != nil {
				break
			}
		}
		done <- builder.String()
	}()

	f()
	write.Close()
	os.Stdout = original
	return <-done
}

// A marketplace nobody could read contributes zero to every count, so the summary of a
// failed run is character-for-character the summary of a clean one — and it is the last
// thing on screen, which is the part people read. The run must end by saying what it did
// not check, not by showing reassuring zeros.
func TestAnUnreadableMarketplaceIsNotReportedAsNothingToDo(t *testing.T) {
	output := capture(t, func() {
		writeReconcileReport(nil, []string{"acme: cannot fetch the catalog index"}, t.TempDir(), false)
	})

	if !strings.Contains(output, "could not be read") {
		t.Fatalf("the summary hides the failure:\n%s", output)
	}
	// The caveat has to come after the counts it invalidates; above them it is the line
	// people scroll past.
	counts := strings.Index(output, "0 verified")
	caveat := strings.Index(output, "could not be read")
	if counts < 0 || caveat < counts {
		t.Fatalf("the caveat must follow the counts:\n%s", output)
	}
}

// The exit code is what a script reads, and an unreadable marketplace is not success.
func TestAnUnreadableMarketplaceIsAnError(t *testing.T) {
	var code int
	capture(t, func() {
		code = writeReconcileReport(nil, []string{"acme: unreachable"}, t.TempDir(), false)
	})
	if code == exitClean {
		t.Fatal("a run that checked nothing must not exit clean")
	}
}

// Found by using the tool rather than by reading it. A machine following two catalogs that
// sign sixteen plugins between them, with none of the sixteen installed, was told:
//
//	16 signed plugins · 0 verified · 0 needing attention
//
// Every figure correct, and the line reads as a clean verification of sixteen things. It is
// the same failure the unreadable-marketplace test above exists for — a run that verified
// nothing looking exactly like a run where nothing was wrong — fixed there and missed here.
func TestPluginsThatAreNotInstalledAreNotReportedAsVerified(t *testing.T) {
	absent := make([]marketplace.Result, 16)
	for i := range absent {
		absent[i] = marketplace.Result{Outcome: marketplace.OutcomeAbsent, Plugin: "signed-elsewhere"}
	}

	output := capture(t, func() {
		writeReconcileReport(absent, nil, t.TempDir(), false)
	})

	if !strings.Contains(output, "16 not installed here") {
		t.Errorf("the counts must add up to the first number:\n%s", output)
	}
	if !strings.Contains(output, "Nothing was verified") {
		t.Errorf("a run that verified nothing must say so in words:\n%s", output)
	}
	// It must not be phrased as an alarm either. Following a catalog whose plugins you have
	// not installed is an ordinary state, and a tool that shouts about it gets ignored when
	// it shouts about something real.
	if !strings.Contains(output, "fine if you did not expect them here") {
		t.Errorf("the sentence must not read as a failure:\n%s", output)
	}
}

// The plain all-clear survives. When plugins really were verified, nothing must suggest
// otherwise — a caveat printed after a genuine success is how a reader learns to skip them.
func TestAVerifiedRunIsNotToldNothingWasVerified(t *testing.T) {
	output := capture(t, func() {
		writeReconcileReport([]marketplace.Result{
			{Outcome: marketplace.OutcomeVerified, Plugin: "delegate"},
			{Outcome: marketplace.OutcomeAbsent, Plugin: "not-here"},
		}, nil, t.TempDir(), false)
	})

	if strings.Contains(output, "Nothing was verified") {
		t.Errorf("one plugin verified is not nothing:\n%s", output)
	}
	if !strings.Contains(output, "1 verified · 1 not installed here") {
		t.Errorf("both buckets must be visible:\n%s", output)
	}
}

// A run that genuinely had nothing to do says so without a caveat that would train
// readers to ignore it.
func TestACleanRunCarriesNoCaveat(t *testing.T) {
	output := capture(t, func() {
		writeReconcileReport(
			[]marketplace.Result{{Outcome: marketplace.OutcomeVerified, Plugin: "delegate"}},
			nil, t.TempDir(), false)
	})

	if strings.Contains(output, "could not be read") {
		t.Fatalf("a clean run warns about nothing:\n%s", output)
	}
	if !strings.Contains(output, "1 verified") {
		t.Fatalf("the clean summary is wrong:\n%s", output)
	}
}

func serveSignedCatalog(
	t *testing.T, snapshot catalog.Snapshot, key ed25519.PrivateKey,
) *httptest.Server {
	t.Helper()
	envelope, err := catalog.Sign(snapshot, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func writeCatalogIndex(
	t *testing.T, subscription Subscription, snapshot catalog.Snapshot, key ed25519.PrivateKey,
) {
	t.Helper()
	envelope, err := catalog.Sign(snapshot, key)
	if err != nil {
		t.Fatal(err)
	}
	path := indexPath(subscription)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Save(path); err != nil {
		t.Fatal(err)
	}
}

func TestSessionStartRefreshesCatalogsByDefault(t *testing.T) {
	home := t.TempDir()
	claudeHome := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", public); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	refreshed := catalog.Snapshot{
		Version: catalog.SnapshotVersion,
		Name:    "acme", Sequence: 2,
		IssuedAt: now, ValidUntil: now.Add(time.Hour),
		Skills:  []catalog.Managed{{Name: "runbook", Digest: "sha256:aaa", Version: "1.0.0"}},
		Revoked: []catalog.Entry{{Digest: "sha256:aaa", Reason: "withdrawn", RevokedAt: now}},
	}
	server := serveSignedCatalog(t, refreshed, private)

	subscription := Subscription{
		Name:       "acme",
		Repository: "/no/such/repository",
		CatalogURL: server.URL + "/v1/catalogs/acme/plugins",
		KeyIDs:     []string{attest.KeyID(public)},
	}
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}

	writeCatalogIndex(t, subscription, catalog.Snapshot{
		Version: catalog.SnapshotVersion,
		Name:    "acme", Sequence: 1,
		IssuedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
		Skills: []catalog.Managed{{Name: "runbook", Digest: "sha256:aaa", Version: "1.0.0"}},
	}, private)

	if code := runHookSessionStart([]string{"--claude-home", claudeHome}); code != exitClean {
		t.Fatalf("session-start = %d", code)
	}

	state, err := catalog.LoadState(statePath("acme.sequence"))
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 2 {
		t.Fatalf("sequence = %d, want the refreshed catalog", state.Sequence)
	}
}

func TestARejectedRefreshFallsBackToTheCachedCatalog(t *testing.T) {
	home := t.TempDir()
	claudeHome := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", public); err != nil {
		t.Fatal(err)
	}

	subscription := Subscription{
		Name:       "acme",
		Repository: "/no/such/repository",
		CatalogURL: "https://example.invalid/v1/catalogs/acme/plugins",
		KeyIDs:     []string{attest.KeyID(public)},
	}
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	cached := catalog.Snapshot{
		Version: catalog.SnapshotVersion,
		Name:    "acme", Sequence: 1,
		IssuedAt: now, ValidUntil: now.Add(time.Hour),
		Skills: []catalog.Managed{{Name: "runbook", Digest: "sha256:aaa", Version: "1.0.0"}},
	}
	writeCatalogIndex(t, subscription, cached, private)
	before, err := os.ReadFile(indexPath(subscription))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>sign in</html>"))
	}))
	t.Cleanup(server.Close)
	subscription.CatalogURL = server.URL + "/v1/catalogs/acme/plugins"
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}

	results, unusable, code := reconcileAll(claudeHome, true, false)
	if code != exitClean {
		t.Fatalf("reconcile = %d", code)
	}
	if len(unusable) != 0 {
		t.Fatalf("refresh should fall back to the cached catalog, got %v", unusable)
	}
	if len(results) != 1 || results[0].Outcome != marketplace.OutcomeAbsent {
		t.Fatalf("results = %+v", results)
	}

	after, err := os.ReadFile(indexPath(subscription))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("a rejected refresh replaced the last trusted catalog")
	}
}

func TestRevocationFromAFreshCatalogStillAppliesWhenTheRepositoryCannotRefresh(t *testing.T) {
	home := t.TempDir()
	claudeHome := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", public); err != nil {
		t.Fatal(err)
	}

	installed := marketplace.InstalledPath(claudeHome, "acme", "runbook", "1.0.0")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, "SKILL.md"),
		[]byte("---\nname: runbook\n---\nfollow it\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _, err := marketplace.DigestInstalled(installed)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	server := serveSignedCatalog(t, catalog.Snapshot{
		Version: catalog.SnapshotVersion,
		Name:    "acme", Sequence: 1,
		IssuedAt: now, ValidUntil: now.Add(time.Hour),
		Skills:  []catalog.Managed{{Name: "runbook", Digest: digest, Version: "1.0.0"}},
		Revoked: []catalog.Entry{{Digest: digest, Reason: "withdrawn", RevokedAt: now}},
	}, private)

	if err := saveSubscriptions([]Subscription{{
		Name:       "acme",
		Repository: "/no/such/repository",
		CatalogURL: server.URL + "/v1/catalogs/acme/plugins",
		KeyIDs:     []string{attest.KeyID(public)},
	}}); err != nil {
		t.Fatal(err)
	}

	results, unusable, code := reconcileAll(claudeHome, true, false)
	if code != exitClean {
		t.Fatalf("reconcile = %d", code)
	}
	if len(unusable) != 0 {
		t.Fatalf("revocation must not be hidden behind a source refresh failure: %v", unusable)
	}
	if len(results) != 1 || results[0].Outcome != marketplace.OutcomeRevoked {
		t.Fatalf("results = %+v", results)
	}
}

func TestSyncReportsManagedChecksAcrossManagedHomesWithoutRestoringTheOtherHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	machinePublic, machinePrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), machinePrivate); err != nil {
		t.Fatal(err)
	}

	publisher, publisherPrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", publisher); err != nil {
		t.Fatal(err)
	}

	rootHome := t.TempDir()
	claudeHome := filepath.Join(rootHome, ".claude")
	codexHome := filepath.Join(rootHome, ".codex")

	good := marketplace.InstalledPath(claudeHome, "acme", "runbook", "1.0.0")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "SKILL.md"),
		[]byte("---\nname: runbook\n---\ncurrent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _, err := marketplace.DigestInstalled(good)
	if err != nil {
		t.Fatal(err)
	}

	changed := marketplace.InstalledPath(codexHome, "acme", "runbook", "1.0.0")
	if err := os.MkdirAll(changed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(changed, "SKILL.md"),
		[]byte("---\nname: runbook\n---\nedited\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	subscription := Subscription{
		Name:       "acme",
		Repository: "/no/such/repository",
		KeyIDs:     []string{attest.KeyID(publisher)},
	}
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}
	writeCatalogIndex(t, subscription, catalog.Snapshot{
		Version:    catalog.SnapshotVersion,
		Name:       "acme",
		Sequence:   1,
		IssuedAt:   time.Now().UTC().Truncate(time.Second),
		ValidUntil: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		Skills:     []catalog.Managed{{Name: "runbook", Digest: digest, Version: "1.0.0"}},
	}, publisherPrivate)

	t.Setenv("HOME", rootHome)
	t.Setenv("USERPROFILE", rootHome)
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)

	if code := runSync([]string{"--agent", "claude", "--offline", "--report-only"}); code != exitClean {
		t.Fatalf("sync = %d", code)
	}

	envelope, err := attest.LoadEnvelope(filepath.Join(home, "events", "check-managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	check, _, err := report.VerifyCheck(envelope, attest.NewTrustedKeys(machinePublic))
	if err != nil {
		t.Fatal(err)
	}
	if check.Checked != 2 {
		t.Fatalf("checked = %d, want both managed homes counted", check.Checked)
	}
	if check.Changed != 1 {
		t.Fatalf("changed = %d, want the untouched second home reported", check.Changed)
	}
	if check.Healthy() {
		t.Fatal("an aggregated sync check with a changed second home must not read healthy")
	}

	raw, err := os.ReadFile(filepath.Join(changed, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "edited") {
		t.Fatal("sync restored the non-selected managed home")
	}
}
