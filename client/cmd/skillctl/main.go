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
  skillctl digest [flags] [path] compute the canonical digest of a skill directory
  skillctl lint [flags] [path]   inventory a tree of skills and report risk indicators
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
	absolute, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
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
