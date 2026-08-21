// Command skillctl is the SkillTrust client: an offline, single-binary tool for taking
// inventory of Agent Skills, and later for pinning, verifying and reconciling them.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/random1st/skilltrust/client/internal/lint"
)

// Build metadata, injected at release time with -ldflags.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// Exit codes are part of the contract: a pipeline must be able to tell "we checked and it
// is bad" apart from "we could not check".
const (
	exitClean    = 0
	exitFindings = 1
	exitUsage    = 3
)

const usage = `skillctl - inventory and verify Agent Skills

Usage:
  skillctl lint [flags] [path]   inventory a tree of skills and report risk indicators
  skillctl digest [flags] [path] compute the canonical digest of a skill directory
  skillctl lock [flags] [path]   pin every skill by digest into skills.lock
  skillctl verify [flags] [path] report drift against skills.lock
  skillctl hook <subcommand>     run or install the session-start drift check
  skillctl version               print version information

Run "skillctl <command> -h" for per-command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}

	switch os.Args[1] {
	case "digest":
		os.Exit(runDigest(os.Args[2:]))
	case "lock":
		os.Exit(runLock(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "hook":
		os.Exit(runHook(os.Args[2:]))
	case "lint":
		os.Exit(runLint(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println(versionString())
		os.Exit(exitClean)
	case "help", "--help", "-h":
		fmt.Print(usage)
		os.Exit(exitClean)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(exitUsage)
	}
}

func runLint(args []string) int {
	flags := flag.NewFlagSet("lint", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl lint [flags] [path]\n\n"+
			"Scans for directories containing SKILL.md and reports specification\n"+
			"deviations and content risk indicators. Runs entirely offline.\n\n"+
			"Exit codes: %d clean, %d findings at or above --fail-on, %d usage error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	format := flags.String("format", "text", "output format: text, json or sarif")
	failOn := flags.String("fail-on", "high",
		"exit non-zero at this severity or above: high, medium, low, info, never")
	output := flags.String("output", "", "write the report to a file instead of stdout")
	maxDepth := flags.Int("max-depth", lint.DefaultMaxDepth, "maximum directory depth to scan")
	maxDirs := flags.Int("max-dirs", lint.DefaultMaxDirectories,
		"maximum number of directories to visit")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	root := "."
	if flags.NArg() > 0 {
		root = flags.Arg(0)
	}
	absolute, note, err := resolvePath(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}

	var threshold lint.Severity
	if strings.ToLower(*failOn) != "never" {
		parsed, ok := lint.ParseSeverity(*failOn)
		if !ok {
			fmt.Fprintf(os.Stderr, "skillctl: unknown --fail-on value %q\n", *failOn)
			return exitUsage
		}
		threshold = parsed
	}

	report := lint.Run(absolute, lint.Options{MaxDepth: *maxDepth, MaxDirectories: *maxDirs})

	writer := io.Writer(os.Stdout)
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
			return exitUsage
		}
		defer file.Close()
		writer = file
	}

	if err := render(writer, report, *format); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	if threshold != "" && report.AtOrAbove(threshold) > 0 {
		return exitFindings
	}
	return exitClean
}

func render(writer io.Writer, report *lint.Report, format string) error {
	switch strings.ToLower(format) {
	case "text":
		return lint.RenderText(writer, report)
	case "json":
		return lint.RenderJSON(writer, report)
	case "sarif":
		return lint.RenderSARIF(writer, report, versionString())
	default:
		return fmt.Errorf("unknown --format %q; use text, json or sarif", format)
	}
}

// resolvePath returns the absolute path a command will actually operate on, plus a note
// when getting there crossed a symlink.
//
// A skills directory is very often a symlink (~/.claude/skills -> ~/.agents/skills is a
// common layout), so following one is normal and must not be an error. What is dangerous
// is following one silently: a copy made with `cp -R` of a symlinked directory is a
// symlink, not a copy, and every "sandboxed" write lands on the original. Printing the
// resolved path makes that mistake visible the first time instead of the hard way.
func resolvePath(raw string) (string, string, error) {
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return absolute, "", nil
	}
	if resolved == absolute {
		return absolute, "", nil
	}
	return resolved, fmt.Sprintf("%s is a symlink to %s", absolute, resolved), nil
}

func versionString() string {
	parts := []string{"skillctl " + resolveVersion()}
	if commit != "" {
		parts = append(parts, "commit "+commit)
	}
	if date != "" {
		parts = append(parts, "built "+date)
	}
	parts = append(parts, fmt.Sprintf("%s/%s %s", runtime.GOOS, runtime.GOARCH, runtime.Version()))
	return strings.Join(parts, " · ")
}

// resolveVersion prefers the release ldflag and falls back to module metadata, so a
// `go install`ed binary still reports something meaningful.
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return version
}
