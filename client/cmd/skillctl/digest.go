package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/random1st/skilltrust/client/internal/archive"
)

// runDigest computes the canonical identity of a directory.
//
// It deliberately takes no source-control arguments. Anyone holding the folder must be
// able to re-derive the digest and check it against a published one; a command that first
// demands a clone URL and a commit SHA cannot serve that purpose, and without independent
// re-derivation "the verifier said so" is the only evidence there is.
func runDigest(args []string) int {
	flags := flag.NewFlagSet("digest", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl digest [flags] [path]\n\n"+
			"Computes the canonical archive digest of a directory. Deterministic and\n"+
			"offline: the same tree yields the same digest on any machine, so a second\n"+
			"party can re-derive it independently.\n\n"+
			"Exit codes: %d ok, %d digest mismatch, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	format := flags.String("format", "text", "output format: text or json")
	expect := flags.String("expect", "", "fail unless the computed digest equals this value")
	quiet := flags.Bool("quiet", false, "print only the digest")

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
	if note != "" && !*quiet {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}

	result, err := archive.Build(absolute, archive.Limits{})
	if err != nil {
		var packaging *archive.Error
		if ok := asArchiveError(err, &packaging); ok {
			fmt.Fprintf(os.Stderr, "skillctl: %s: %s\n", packaging.Kind, packaging.Message)
		} else {
			fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		}
		return exitUsage
	}

	if *expect != "" && !strings.EqualFold(*expect, result.Digest) {
		fmt.Fprintf(os.Stderr,
			"skillctl: digest mismatch\n  expected %s\n  computed %s\n", *expect, result.Digest)
		return exitFindings
	}

	if err := renderDigest(os.Stdout, result, *format, *quiet); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}
	return exitClean
}

func renderDigest(out io.Writer, result *archive.Archive, format string, quiet bool) error {
	if quiet {
		_, err := fmt.Fprintln(out, result.Digest)
		return err
	}

	switch strings.ToLower(format) {
	case "text":
		fmt.Fprintf(out, "%s\n", result.Digest)
		fmt.Fprintf(out, "%d files · %d archive bytes\n\n", len(result.Files), len(result.Payload))
		for _, file := range result.Files {
			marker := " "
			if file.Executable {
				marker = "x"
			}
			fmt.Fprintf(out, "  %s %-12s %8d  %s\n",
				marker, shortDigest(file.Digest), file.Size, file.Path)
		}
		return nil
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	default:
		return fmt.Errorf("unknown --format %q; use text or json", format)
	}
}

func shortDigest(digest string) string {
	trimmed := strings.TrimPrefix(digest, "sha256:")
	if len(trimmed) > 12 {
		return trimmed[:12]
	}
	return trimmed
}

func asArchiveError(err error, target **archive.Error) bool {
	converted, ok := err.(*archive.Error)
	if ok {
		*target = converted
	}
	return ok
}
