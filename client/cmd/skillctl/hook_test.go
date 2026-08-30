package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
