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

const usage = `skillctl - keep your organisation's skills the ones it published

Following a catalog (on a machine):
  skillctl subscribe <git-url> --key <pub>
                                 follow an organisation's signed skill catalog
  skillctl sync                  fetch, verify, and reconcile managed skills
  skillctl status                what is managed here, and whether it matches
  skillctl hook <subcommand>     run or install the session-start reconciler

Publishing a catalog (in a repository of skills):
  skillctl init                  create the signing key this machine publishes with
  skillctl catalog publish       sign the index of skills the repository publishes
  skillctl catalog revoke        revoke digests in that index
  skillctl catalog show          verify an index and print it

Looking at skills:
  skillctl lint [path]           inventory a tree and report risk indicators
  skillctl digest <dir>          the canonical digest of a skill directory
  skillctl attest <subcommand>   sign and verify a statement about a digest
  skillctl version               print version information

Skills no catalog claims are never touched or reported on.
Run "skillctl <command> -h" for per-command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}

	switch os.Args[1] {
	case "subscribe":
		os.Exit(runSubscribe(os.Args[2:]))
	case "init":
		os.Exit(runInit(os.Args[2:]))
	case "status":
		os.Exit(runStatus(os.Args[2:]))
	case "digest":
		os.Exit(runDigest(os.Args[2:]))
	case "hook":
		os.Exit(runHook(os.Args[2:]))
	case "attest":
		os.Exit(runAttest(os.Args[2:]))
	case "catalog":
		os.Exit(runCatalog(os.Args[2:]))
	case "sync":
		os.Exit(runSync(os.Args[2:]))
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

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	absolute, err := resolveSkillRoot(flags.Arg(0))
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

// parseArgs accepts flags and positional arguments in any order.
//
// Go's flag package stops at the first non-flag token, so `attest sign demo --key k` would
// silently print usage and exit 3 while `attest sign --key k demo` worked. In a script that
// reads as an unexplained failure, and a security tool that is fussy about argument order
// is one people wrap in something that gets the order wrong once.
func parseArgs(flags *flag.FlagSet, args []string) error {
	var options, positional []string

	for index := 0; index < len(args); index++ {
		token := args[index]
		if token == "--" {
			positional = append(positional, args[index+1:]...)
			break
		}
		if len(token) < 2 || token[0] != '-' {
			positional = append(positional, token)
			continue
		}

		options = append(options, token)
		name := strings.TrimLeft(token, "-")
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			continue // --flag=value carries its own value
		}
		definition := flags.Lookup(name)
		if definition == nil {
			continue // unknown: let flag.Parse produce the error
		}
		if boolean, ok := definition.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue // boolean flags never consume the next token
		}
		if index+1 < len(args) {
			index++
			options = append(options, args[index])
		}
	}

	// The explicit terminator matters: a positional that begins with a dash (a path like
	// -weird, or anything after an author's own --) must not be re-read as a flag once the
	// two groups are concatenated.
	reordered := append(options, "--")
	return flags.Parse(append(reordered, positional...))
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
	if resolved == absolute || isPlatformPrefixRewrite(absolute, resolved) {
		return resolved, "", nil
	}
	return resolved, fmt.Sprintf("%s is a symlink to %s", absolute, resolved), nil
}

// isPlatformPrefixRewrite reports the macOS case where /var, /tmp and /etc are symlinks
// into /private. Those hops are true but say nothing about the user's layout, and a
// warning that fires on every temp directory is one people stop reading — the same alert
// fatigue this tool avoids elsewhere by demoting prohibitions instead of shouting.
func isPlatformPrefixRewrite(absolute, resolved string) bool {
	return runtime.GOOS == "darwin" && resolved == "/private"+absolute
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
