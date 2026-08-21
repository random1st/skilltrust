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

	if err := flags.Parse(args); err != nil {
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

	if err := flags.Parse(args); err != nil {
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

	lock, err := lockfile.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr,
				"skillctl: no lock at %s; run `skillctl lock` first to pin the current tree\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		}
		return exitUsage
	}

	report := lockfile.Verify(root, path, lock, lint.Options{MaxDepth: *maxDepth})

	if err := renderVerify(os.Stdout, report, *format); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	if report.Drifted() > 0 || (*frozen && report.Unpinned() > 0) {
		return exitFindings
	}
	return exitClean
}

func resolveRoot(flags *flag.FlagSet) (string, error) {
	root := "."
	if flags.NArg() > 0 {
		root = flags.Arg(0)
	}
	resolved, note, err := resolvePath(root)
	if err != nil {
		return "", err
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}
	return resolved, nil
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
		fmt.Fprintf(out, "             %s\n", result.Path)

		switch result.Status {
		case lockfile.StatusModified:
			fmt.Fprintf(out, "             pinned   %s\n", result.Expected)
			fmt.Fprintf(out, "             on disk  %s\n", result.Actual)
			for _, change := range result.Changes {
				fmt.Fprintf(out, "               %-12s %s\n", change.Change, change.Path)
			}
		case lockfile.StatusRemoved:
			fmt.Fprintf(out, "             pinned   %s\n", result.Expected)
		case lockfile.StatusUnreadable:
			fmt.Fprintf(out, "             %s\n", result.Message)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "%d matched · %d drifted · %d unpinned\n",
		matched, report.Drifted(), report.Unpinned())
	if report.Drifted() == 0 && report.Unpinned() == 0 {
		fmt.Fprintln(out, "every pinned skill is byte-identical to what was recorded.")
	}
	return nil
}
