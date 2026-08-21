package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
	"github.com/random1st/skilltrust/client/internal/receipt"
)

func writeSkill(t *testing.T, root, name string) {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: " + name + "\ndescription: A demo skill.\n---\n\nBody.\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func pin(t *testing.T, root string) {
	t.Helper()
	lock, err := lockfile.Build(root, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Save(filepath.Join(root, lockfile.FileName)); err != nil {
		t.Fatal(err)
	}
}

// A lock that is absent and a lock that cannot be read are different facts and must not be
// reported the same way. Conflating them hands an attacker a silent off switch: corrupt the
// file and the session-start check disappears without a trace.
func TestVerifyRootsSeparatesMissingFromUnreadable(t *testing.T) {
	unpinned := t.TempDir()
	writeSkill(t, unpinned, "alpha")

	pinned := t.TempDir()
	writeSkill(t, pinned, "alpha")
	pin(t, pinned)

	corrupt := t.TempDir()
	writeSkill(t, corrupt, "alpha")
	if err := os.WriteFile(filepath.Join(corrupt, lockfile.FileName),
		[]byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	reports, broken := verifyRoots([]string{unpinned, pinned, corrupt})

	if len(reports) != 1 {
		t.Fatalf("only the pinned tree should produce a report, got %d", len(reports))
	}
	if len(broken) != 1 {
		t.Fatalf("the corrupt lock must be reported, got %v", broken)
	}
	if !strings.Contains(broken[0], corrupt) {
		t.Fatalf("broken = %v", broken)
	}
}

func TestHookReportNamesTheChangedFile(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "alpha")
	pin(t, root)

	skillFile := filepath.Join(root, "alpha", "SKILL.md")
	existing, err := os.ReadFile(skillFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skillFile, append(existing, []byte("\nextra\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	reports, broken := verifyRoots([]string{root})
	buffer := &strings.Builder{}
	writeHookReport(buffer, reports, broken)

	output := buffer.String()
	for _, want := range []string{"alpha", "modified SKILL.md", "detection, not enforcement"} {
		if !strings.Contains(output, want) {
			t.Fatalf("report is missing %q:\n%s", want, output)
		}
	}
}

// Following a symlink is normal, hiding it is not: `cp -R` of a symlinked directory
// produces another symlink, so writes meant for a sandbox land on the original.
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

// A tree whose skills arrived through `skillctl install` has a recorded digest for every one
// of them. Skipping it because nobody typed `lock` meant the hook stayed silent about exactly
// the trees this tool had itself populated.
func TestVerifyRootsChecksAReceiptOnlyTree(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "alpha")

	built, err := archive.Build(filepath.Join(root, "alpha"), archive.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	record := &receipt.Receipt{Name: "alpha", Digest: built.Digest, Source: "alpha.tar"}
	if err := record.Save(receipt.Path(root, "alpha")); err != nil {
		t.Fatal(err)
	}

	reports, broken := verifyRoots([]string{root})
	if len(reports) != 1 || len(broken) != 0 {
		t.Fatalf("reports = %d, broken = %v", len(reports), broken)
	}
	if reports[0].Drifted() != 0 || reports[0].Unpinned() != 0 {
		t.Fatalf("a freshly installed tree must verify clean: %+v", reports[0].Results)
	}

	edited := filepath.Join(root, "alpha", "SKILL.md")
	if err := os.WriteFile(edited, []byte("---\nname: alpha\ndescription: Edited.\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reports, _ = verifyRoots([]string{root})
	if reports[0].Drifted() != 1 {
		t.Fatalf("drifted = %d; the hook must see drift against an install receipt",
			reports[0].Drifted())
	}
}

// The bug this pins was found the first time the tool was pointed at a real machine:
// ~/.claude/skills is a symlink to ~/.agents/skills, so the conventional locations named
// one tree four times. The hook verified it four times and reported 388 skills where there
// are 97 — and had anything drifted, it would have printed each drifted skill four times in
// the one report a person reads at the start of a session.
func TestCandidateRootsCollapsesOneTreeNamedTwice(t *testing.T) {
	real := t.TempDir()
	writeSkill(t, real, "alpha")

	link := filepath.Join(t.TempDir(), "skills")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	roots := candidateRoots([]string{real, link, real})
	if len(roots) != 1 {
		t.Fatalf("roots = %v; one directory under several names is one tree", roots)
	}
}
