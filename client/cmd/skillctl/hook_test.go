package main

import (
	"encoding/json"
	"flag"
	"io"
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

func TestResolvePathReportsSymlinkHops(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "looks-like-a-copy")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	resolved, note, err := resolvePath(link)
	if err != nil {
		t.Fatal(err)
	}
	if note == "" {
		t.Fatal("crossing a symlink must be reported")
	}
	expected, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != expected {
		t.Fatalf("resolved = %s, want %s", resolved, expected)
	}

	// Compare against the already-resolved path: on macOS /var is itself a symlink to
	// /private/var, so a temp directory legitimately produces a note.
	if _, note, err := resolvePath(expected); err != nil || note != "" {
		t.Fatalf("an already-resolved path must produce no note: note=%q err=%v", note, err)
	}
}

// Go's flag package stops at the first non-flag token, so without permutation
// `attest sign demo --key k` would print usage and exit 3 while the same command with the
// path last worked. A tool that is fussy about argument order gets wrapped in a script
// that gets the order wrong exactly once.
func TestParseArgsAcceptsEitherOrder(t *testing.T) {
	build := func() (*flag.FlagSet, *string, *bool) {
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		key := flags.String("key", "", "")
		force := flags.Bool("force", false, "")
		return flags, key, force
	}

	cases := map[string][]string{
		"flags first":      {"--key", "k", "--force", "demo"},
		"positional first": {"demo", "--key", "k", "--force"},
		"interleaved":      {"--key", "k", "demo", "--force"},
		"equals form":      {"demo", "--key=k", "--force"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			flags, key, force := build()
			if err := parseArgs(flags, args); err != nil {
				t.Fatal(err)
			}
			if *key != "k" || !*force {
				t.Fatalf("key=%q force=%v", *key, *force)
			}
			if flags.NArg() != 1 || flags.Arg(0) != "demo" {
				t.Fatalf("positional = %v", flags.Args())
			}
		})
	}
}

func TestParseArgsStopsAtDoubleDash(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	key := flags.String("key", "", "")

	if err := parseArgs(flags, []string{"--key", "k", "--", "--not-a-flag"}); err != nil {
		t.Fatal(err)
	}
	if *key != "k" {
		t.Fatalf("key = %q", *key)
	}
	if flags.NArg() != 1 || flags.Arg(0) != "--not-a-flag" {
		t.Fatalf("positional = %v", flags.Args())
	}
}

// Installing the hook must be safe to repeat, and must be removable. A check that can only
// be added is one people are right to refuse to add.
func TestHookInstallIsIdempotentAndReversible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"model":"opus","hooks":{"SessionStart":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	specs := claudeHooks("/usr/local/bin/skillctl")

	added, err := applyClaudeHooks(path, specs)
	if err != nil || len(added) != 1 {
		t.Fatalf("added = %d, err = %v", len(added), err)
	}
	again, err := applyClaudeHooks(path, specs)
	if err != nil || len(again) != 0 {
		t.Fatalf("a second install must add nothing, got %d (%v)", len(again), err)
	}

	// Unrelated settings must survive: rewriting a client's file with a narrower schema is
	// how a tool breaks the client it was only supposed to observe.
	var document map[string]any
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["model"] != "opus" {
		t.Fatalf("unrelated settings were lost: %v", document)
	}

	removed, err := removeClaudeHooks(path, "skillctl")
	if err != nil || removed != 1 {
		t.Fatalf("removed = %d, err = %v", removed, err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "skillctl") {
		t.Fatalf("uninstall must leave nothing behind:\n%s", raw)
	}
}

// The flag is the contract the console quotes. applyClaudeHooks writing a file is not the
// same as `hook install --apply` writing one: a reader who runs the documented command
// without --apply is told the check runs every session while nothing was installed.
func TestHookInstallApplyWritesSettingsAndWithoutItDoesNot(t *testing.T) {
	dir := t.TempDir()
	applied := filepath.Join(dir, "applied.json")
	if code := runHookInstall([]string{"--client", "claude", "--settings", applied, "--apply"}); code != 0 {
		t.Fatalf("hook install --apply exited %d", code)
	}
	raw, err := os.ReadFile(applied)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "hook session-start") {
		t.Fatalf("--apply did not write the session-start hook:\n%s", raw)
	}

	printed := filepath.Join(dir, "printed.json")
	if err := os.WriteFile(printed, []byte("{\"model\":\"opus\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runHookInstall([]string{"--client", "claude", "--settings", printed}); code != 0 {
		t.Fatalf("hook install without --apply exited %d", code)
	}
	left, err := os.ReadFile(printed)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != "{\"model\":\"opus\"}\n" {
		t.Fatalf("without --apply the settings file was rewritten:\n%s", left)
	}
}

func TestSessionStartFlushesPendingEventsEvenWithoutNewIncidents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)

	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}

	recordEvents([]marketplace.Result{{
		Marketplace: "acme", Plugin: "runbook", Version: "1.0.0",
		Outcome: marketplace.OutcomeRestored, Quarantine: "/tmp/runbook",
	}}, nil, time.Now().UTC())

	delivery := filepath.Join(t.TempDir(), "delivered")
	if err := saveHomeJSON(reportConfigPath(), report.Config{
		Destinations: []report.Destination{{Kind: "file", Directory: delivery}},
	}); err != nil {
		t.Fatal(err)
	}

	if code := runHookSessionStart(nil); code != exitClean {
		t.Fatalf("session-start = %d", code)
	}

	entries, err := os.ReadDir(delivery)
	if err != nil {
		t.Fatalf("no report was delivered: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("delivered files = %d, want 1", len(entries))
	}
	pending, err := os.ReadDir(filepath.Join(home, "events"))
	if err != nil {
		t.Fatalf("cannot read the spool after session-start: %v", err)
	}
	for _, entry := range pending {
		if filepath.Ext(entry.Name()) == ".json" {
			t.Fatalf("session-start left %s in the spool", entry.Name())
		}
	}
}

func TestSessionStartAggregatesManagedChecksAcrossManagedHomes(t *testing.T) {
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

	if code := runHookSessionStart([]string{"--fetch=false"}); code != exitClean {
		t.Fatalf("session-start = %d", code)
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
	if check.Errors != 1 {
		t.Fatalf("errors = %d, want the changed second home reported as unchecked", check.Errors)
	}
	if check.Healthy() {
		t.Fatal("an aggregated check with one unverifiable managed home must not read healthy")
	}
}

func TestMergeManagedChecksKeepsMostConservativeCatalogEvidenceAcrossHomes(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	t.Run("lower sequence wins", func(t *testing.T) {
		merged := mergeManagedChecks(
			ManagedCheck{
				Scope:     CheckScopeManaged,
				Coverage:  "full",
				Complete:  true,
				CheckedAt: now,
				Catalogs: []ManagedCatalogCheck{{
					Name:       "acme",
					Sequence:   2,
					ValidUntil: now.Add(2 * time.Hour),
					Refreshed:  true,
				}},
			},
			ManagedCheck{
				Scope:     CheckScopeManaged,
				Coverage:  "full",
				Complete:  true,
				CheckedAt: now.Add(time.Minute),
				Catalogs: []ManagedCatalogCheck{{
					Name:       "acme",
					Sequence:   1,
					ValidUntil: now.Add(20 * time.Hour),
					UsedCached: true,
				}},
			},
		)

		if len(merged.Catalogs) != 1 {
			t.Fatalf("catalog count = %d, want 1", len(merged.Catalogs))
		}
		catalog := merged.Catalogs[0]
		if catalog.Sequence != 1 {
			t.Fatalf("sequence = %d, want lower sequence 1", catalog.Sequence)
		}
		if !catalog.ValidUntil.Equal(now.Add(2 * time.Hour)) {
			t.Fatalf("valid until = %s, want earlier expiry %s", catalog.ValidUntil, now.Add(2*time.Hour))
		}
		if !catalog.Refreshed || !catalog.UsedCached {
			t.Fatalf("merged evidence lost metadata: refreshed=%v used_cached=%v", catalog.Refreshed, catalog.UsedCached)
		}
	})

	t.Run("same sequence keeps earlier expiry", func(t *testing.T) {
		merged := mergeManagedChecks(
			ManagedCheck{
				Scope:     CheckScopeManaged,
				Coverage:  "full",
				Complete:  true,
				CheckedAt: now,
				Catalogs: []ManagedCatalogCheck{{
					Name:       "acme",
					Sequence:   2,
					ValidUntil: now.Add(12 * time.Hour),
				}},
			},
			ManagedCheck{
				Scope:     CheckScopeManaged,
				Coverage:  "full",
				Complete:  true,
				CheckedAt: now.Add(time.Minute),
				Catalogs: []ManagedCatalogCheck{{
					Name:       "acme",
					Sequence:   2,
					ValidUntil: now.Add(3 * time.Hour),
				}},
			},
		)

		if len(merged.Catalogs) != 1 {
			t.Fatalf("catalog count = %d, want 1", len(merged.Catalogs))
		}
		catalog := merged.Catalogs[0]
		if catalog.Sequence != 2 {
			t.Fatalf("sequence = %d, want 2", catalog.Sequence)
		}
		if !catalog.ValidUntil.Equal(now.Add(3 * time.Hour)) {
			t.Fatalf("valid until = %s, want earlier expiry %s", catalog.ValidUntil, now.Add(3*time.Hour))
		}
	})
}
