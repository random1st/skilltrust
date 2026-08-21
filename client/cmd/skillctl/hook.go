package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
	"github.com/random1st/skilltrust/client/internal/receipt"
)

// defaultHookRoots are the conventional skill locations. `.agents/skills` is the
// cross-client convention; `.claude/skills` is scanned too because that is where most
// existing skills actually live.
var defaultHookRoots = []string{
	filepath.Join(".agents", "skills"),
	filepath.Join(".claude", "skills"),
}

const hookUsage = `Usage: skillctl hook <subcommand> [flags]

  session-start   verify pinned skills and report drift; intended for a client's
                  SessionStart hook
  install         print (or apply) the client configuration for the hook

`

func runHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, hookUsage)
		return exitUsage
	}
	switch args[0] {
	case "session-start":
		return runHookSessionStart(args[1:])
	case "install":
		return runHookInstall(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown hook subcommand %q\n\n%s", args[0], hookUsage)
		return exitUsage
	}
}

func runHookSessionStart(args []string) int {
	flags := flag.NewFlagSet("hook session-start", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(),
			"Usage: skillctl hook session-start [flags]\n\n"+
				"Verifies every skills directory that has a %s next to it and prints a\n"+
				"report only when something drifted. Silence when clean is deliberate: a\n"+
				"hook that prints on every session spends context it did not earn.\n\n"+
				"Exit codes: %d always, unless --strict is set and drift was found.\n\nFlags:\n",
			lockfile.FileName, exitClean)
		flags.PrintDefaults()
	}

	var roots repeatedFlag
	flags.Var(&roots, "path", "skills directory to check (repeatable; defaults to the standard locations)")
	strict := flags.Bool("strict", false,
		"exit non-zero on drift; most clients treat that as a blocked session")
	verbose := flags.Bool("verbose", false, "also report when everything matches")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	reports, broken := verifyRoots(candidateRoots(roots))
	drifted := 0
	for _, report := range reports {
		drifted += report.Drifted()
	}

	if drifted == 0 && len(broken) == 0 {
		if *verbose {
			total := 0
			for _, report := range reports {
				// Skills nobody recorded are not what this checked, so counting them here
				// would inflate the one number the verbose line exists to report.
				total += len(report.Results) - report.Unpinned()
			}
			fmt.Printf("skillctl: %d recorded skills unchanged\n", total)
		}
		return exitClean
	}

	writeHookReport(os.Stdout, reports, broken)
	if *strict {
		return exitFindings
	}
	return exitClean
}

// candidateRoots resolves the directories to check. A directory without a lock is skipped
// in silence: not pinned means not this tool's business, and warning about it every session
// would train the reader to ignore the hook.
func candidateRoots(explicit []string) []string {
	if len(explicit) > 0 {
		return explicit
	}

	var bases []string
	if working, err := os.Getwd(); err == nil {
		bases = append(bases, working)
	}
	if home, err := os.UserHomeDir(); err == nil {
		bases = append(bases, home)
	}

	var roots []string
	for _, base := range bases {
		for _, suffix := range defaultHookRoots {
			roots = append(roots, filepath.Join(base, suffix))
		}
	}
	return roots
}

// verifyRoots distinguishes three states that must never be conflated.
//
// Nothing recorded — no lock and no install receipts — means the tree is not this tool's
// business and is passed over in silence. A record that exists but cannot be read is the
// opposite: it is a broken promise, and it has to be loud. Treating an unreadable lock like
// a missing one hands an attacker a silent off switch: corrupt the file and the check
// disappears with no trace, which is precisely the failure mode this project exists to
// refuse.
//
// Receipts count as records here for the same reason verify reads them. A tree whose skills
// arrived through `skillctl install` has a recorded digest for every one of them, and a hook
// that stays quiet about drift there because nobody typed `lock` is checking the wrong thing.
func verifyRoots(roots []string) ([]*lockfile.Report, []string) {
	var reports []*lockfile.Report
	var broken []string

	for _, root := range roots {
		lockPath := filepath.Join(root, lockfile.FileName)
		lock := &lockfile.Lock{Version: lockfile.Version}

		if _, err := os.Stat(lockPath); err == nil {
			loaded, err := lockfile.Load(lockPath)
			if err != nil {
				broken = append(broken, fmt.Sprintf(
					"%s exists but could not be read, so nothing there was verified: %v",
					lockPath, err))
				continue
			}
			lock = loaded
		} else if !hasReceipts(root) {
			continue
		}

		report := lockfile.Verify(root, lockPath, lock, lint.Options{})
		reports = append(reports, report)
		broken = append(broken, report.Unchecked...)
	}
	return reports, broken
}

// hasReceipts reports whether anything under root was installed through skillctl.
func hasReceipts(root string) bool {
	info, err := os.Stat(filepath.Join(root, receipt.Directory))
	return err == nil && info.IsDir()
}

func writeHookReport(out io.Writer, reports []*lockfile.Report, broken []string) {
	for _, failure := range broken {
		fmt.Fprintf(out, "skillctl: %s\n\n", failure)
	}

	type row struct{ root, skill, detail string }
	var rows []row
	for _, report := range reports {
		for _, result := range report.Results {
			switch result.Status {
			case lockfile.StatusMatched, lockfile.StatusAdded:
				continue
			}
			label := result.Name
			if label == "" {
				label = result.Path
			}
			rows = append(rows, row{report.Root, label, hookDetail(result)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].skill < rows[j].skill })

	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(out, "skillctl: %d recorded skill(s) changed since they were approved\n\n", len(rows))
	for _, item := range rows {
		fmt.Fprintf(out, "  %-32s %s\n", item.skill, item.detail)
	}
	fmt.Fprintf(out, "\nInspect with: skillctl verify <path>\n")
	fmt.Fprintf(out, "Re-approve with: skillctl lock <path>\n\n")
	// The reader has to know what this guarantee is worth.
	fmt.Fprintf(out, "This is detection, not enforcement: anything able to edit a skill can "+
		"also edit this hook.\n")
}

func hookDetail(result lockfile.Result) string {
	switch result.Status {
	case lockfile.StatusRemoved:
		return "removed"
	case lockfile.StatusUnreadable:
		return "unreadable: " + result.Message
	}

	if len(result.Changes) == 0 {
		return "modified"
	}
	parts := make([]string, 0, len(result.Changes))
	for _, change := range result.Changes {
		parts = append(parts, change.Change+" "+change.Path)
	}
	if len(parts) > 3 {
		return strings.Join(parts[:3], ", ") + fmt.Sprintf(", +%d more", len(parts)-3)
	}
	return strings.Join(parts, ", ")
}

type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ", ") }

func (r *repeatedFlag) Set(value string) error {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return err
	}
	*r = append(*r, absolute)
	return nil
}

func runHookInstall(args []string) int {
	flags := flag.NewFlagSet("hook install", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(),
			"Usage: skillctl hook install [flags]\n\n"+
				"Prints the client configuration that runs the drift check at session start.\n"+
				"Nothing is written unless --apply is given, and --apply keeps a backup.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	client := flags.String("client", "claude", "target client: claude")
	settings := flags.String("settings", "", "settings file to modify (default the client's user settings)")
	apply := flags.Bool("apply", false, "write the change instead of printing it")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if *client != "claude" {
		fmt.Fprintf(os.Stderr, "skillctl: unsupported --client %q\n", *client)
		return exitUsage
	}

	path := *settings
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
			return exitUsage
		}
		path = filepath.Join(home, ".claude", "settings.json")
	}

	executable, err := os.Executable()
	if err != nil {
		executable = "skillctl"
	}
	entry := map[string]any{
		"matcher": "",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": executable + " hook session-start",
		}},
	}

	if !*apply {
		encoded, _ := json.MarshalIndent(entry, "  ", "  ")
		fmt.Printf("Add to %s under hooks.SessionStart:\n\n  %s\n\n", path, encoded)
		fmt.Printf("Apply automatically with: skillctl hook install --apply\n")
		return exitClean
	}

	if err := applyClaudeHook(path, entry); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}
	fmt.Printf("installed into %s (backup at %s.skillctl-backup)\n", path, path)
	return exitClean
}

// applyClaudeHook merges the entry into settings.json without disturbing anything else.
// The whole document is decoded into a generic map and re-encoded, so unknown keys survive
// untouched; rewriting a settings file with a narrower schema is how a tool breaks a
// client it was only supposed to observe.
func applyClaudeHook(path string, entry map[string]any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	if err := os.WriteFile(path+".skillctl-backup", raw, 0o600); err != nil {
		return fmt.Errorf("cannot write a backup: %w", err)
	}

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("%s is not valid JSON: %w", path, err)
	}

	hooks, _ := document["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	existing, _ := hooks["SessionStart"].([]any)

	if hookAlreadyPresent(existing, "hook session-start") {
		return fmt.Errorf("a skillctl session-start hook is already configured in %s", path)
	}

	hooks["SessionStart"] = append(existing, entry)
	document["hooks"] = hooks

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	temporary, err := os.CreateTemp(filepath.Dir(path), ".settings.*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func hookAlreadyPresent(groups []any, needle string) bool {
	for _, group := range groups {
		mapping, ok := group.(map[string]any)
		if !ok {
			continue
		}
		entries, _ := mapping["hooks"].([]any)
		for _, item := range entries {
			hook, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if command, ok := hook["command"].(string); ok && strings.Contains(command, needle) {
				return true
			}
		}
	}
	return false
}
