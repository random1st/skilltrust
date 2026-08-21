package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
)

func runLock(args []string) int {
	flags := flag.NewFlagSet("lock", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl lock [flags] [path]\n\n"+
			"Pins every skill under path by digest into %s. Commit the lock: from then\n"+
			"on any change to a pinned skill is detectable with `skillctl verify`.\n\n"+
			"Exit codes: %d ok, %d error.\n\nFlags:\n",
			lockfile.FileName, exitClean, exitUsage)
		flags.PrintDefaults()
	}

	output := flags.String("output", "", "lock file to write (default <path>/"+lockfile.FileName+")")
	maxDepth := flags.Int("max-depth", lint.DefaultMaxDepth, "maximum directory depth to scan")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	root, err := resolveRoot(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}
	lockPath := *output
	if lockPath == "" {
		lockPath = filepath.Join(root, lockfile.FileName)
	}

	lock, err := lockfile.Build(root, lint.Options{MaxDepth: *maxDepth})
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}
	if err := lock.Save(lockPath); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	fmt.Printf("pinned %d skills to %s\n", len(lock.Skills), lockPath)
	for _, entry := range lock.Skills {
		fmt.Printf("  %s  %-32s %d files\n", shortDigest(entry.Digest), entry.Path, len(entry.Files))
	}
	return exitClean
}

func runVerify(args []string) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl verify [flags] [path]\n\n"+
			"Recomputes every pinned skill and reports drift against %s.\n"+
			"Runs entirely offline.\n\n"+
			"Exit codes: %d clean, %d drift, %d error.\n\nFlags:\n",
			lockfile.FileName, exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	lockPath := flags.String("lock", "", "lock file to verify against (default <path>/"+lockfile.FileName+")")
	frozen := flags.Bool("frozen", false,
		"also fail when a skill on disk is absent from the lock; use this in CI")
	format := flags.String("format", "text", "output format: text or json")
	maxDepth := flags.Int("max-depth", lint.DefaultMaxDepth, "maximum directory depth to scan")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	root, err := resolveRoot(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}
	path := *lockPath
	if path == "" {
		path = filepath.Join(root, lockfile.FileName)
	}

	// A missing lock is only fatal when nothing else recorded these skills. A tree whose
	// skills arrived through `skillctl install` has a digest recorded for every one of them,
	// and refusing to look at it because nobody typed `lock` was how verify came to report
	// a correctly installed tree as unpinned while sync reported it as drifted.
	lock := &lockfile.Lock{Version: lockfile.Version}
	loaded, err := lockfile.Load(path)
	switch {
	case err == nil:
		lock = loaded
	case !os.IsNotExist(err):
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	case !hasReceipts(root):
		fmt.Fprintf(os.Stderr, "skillctl: nothing under %s has been recorded: no lock at %s "+
			"and nothing was installed by skillctl. Run `skillctl lock` to pin the current "+
			"tree\n", root, path)
		return exitUsage
	}

	report := lockfile.Verify(root, path, lock, lint.Options{MaxDepth: *maxDepth})

	if err := renderVerify(os.Stdout, report, *format); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	// Something that could not be examined is never reported through the code that means
	// "examined and fine", however much of the rest of the tree verified cleanly.
	for _, note := range report.Unchecked {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}
	if len(report.Unchecked) > 0 {
		return exitUsage
	}

	if report.Drifted() > 0 || (*frozen && report.Unpinned() > 0) {
		return exitFindings
	}
	return exitClean
}

func resolveRoot(flags *flag.FlagSet) (string, error) {
	return resolveSkillRoot(flags.Arg(0))
}

func renderVerify(out io.Writer, report *lockfile.Report, format string) error {
	if strings.ToLower(format) == "json" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	if strings.ToLower(format) != "text" {
		return fmt.Errorf("unknown --format %q; use text or json", format)
	}

	fmt.Fprintf(out, "skillctl verify  %s\n\n", report.Root)

	matched := 0
	for _, result := range report.Results {
		if result.Status == lockfile.StatusMatched {
			matched++
			continue
		}

		label := result.Name
		if label == "" {
			label = result.Path
		}
		fmt.Fprintf(out, "  %-10s %s\n", result.Status, label)
		if result.Path != "" && result.Path != label {
			fmt.Fprintf(out, "             %s\n", result.Path)
		}

		switch result.Status {
		case lockfile.StatusModified:
			fmt.Fprintf(out, "             %s %s\n", expectedLabel(result.PinnedBy), result.Expected)
			fmt.Fprintf(out, "             on disk   %s\n", result.Actual)
			for _, change := range result.Changes {
				fmt.Fprintf(out, "               %-12s %s\n", change.Change, change.Path)
			}
			if result.Message != "" {
				fmt.Fprintf(out, "             %s\n", result.Message)
			}
		case lockfile.StatusRemoved:
			fmt.Fprintf(out, "             %s %s\n", expectedLabel(result.PinnedBy), result.Expected)
		case lockfile.StatusUnreadable:
			fmt.Fprintf(out, "             %s\n", result.Message)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "%d matched · %d drifted · %d unpinned\n",
		matched, report.Drifted(), report.Unpinned())
	if report.Drifted() == 0 && report.Unpinned() == 0 {
		fmt.Fprintln(out, "every recorded skill is byte-identical to what was recorded.")
	}
	return nil
}

// expectedLabel says which record the expected digest came from, because the remedy differs:
// a broken lock pin is re-approved with `lock`, a broken install record is reinstalled.
func expectedLabel(source lockfile.PinnedBy) string {
	if source == lockfile.PinnedByReceipt {
		return "installed"
	}
	return "pinned   "
}
