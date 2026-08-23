package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/report"
)

// runFleet aggregates the events machines filed, into the view an administrator asks for.
//
// This is a console the way a console should start: a reader over signed files an
// organisation already has, with no service to run, no database and no port to defend. Every
// event carries the signature of the machine that filed it, so what this prints is
// attributable rather than merely collected — and a report nobody signed is refused rather
// than counted, because an aggregate built from unverifiable rows looks like evidence and is
// not.
//
// A hosted console can be built on exactly this later. What it cannot be built on is a fleet
// that never reported.
func runFleet(args []string) int {
	flags := flag.NewFlagSet("fleet", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl fleet [flags] <events-directory>\n\n"+
			"Reads the signed events your machines filed and summarises them: which machines\n"+
			"reported, what was restored or refused, and what went unchecked.\n\n"+
			"Exit codes: %d nothing outstanding, %d something needs attention, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(),
		"keys of the machines allowed to file reports")
	since := flags.Duration("since", 0, "only events newer than this, e.g. 168h")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	directory := flags.Arg(0)
	if directory == "" {
		flags.Usage()
		return exitUsage
	}

	trusted, err := attest.LoadTrustedKeys(*trustedPath)
	if err != nil {
		return fail(err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return fail(err)
	}

	cutoff := time.Time{}
	if *since > 0 {
		cutoff = time.Now().UTC().Add(-*since)
	}

	type machine struct {
		name       string
		last       time.Time
		byKind     map[report.Kind]int
		highlights []report.Event
	}
	machines := map[string]*machine{}
	unattributed := 0

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		envelope, err := attest.LoadEnvelope(filepath.Join(directory, entry.Name()))
		if err != nil {
			unattributed++
			continue
		}
		event, _, err := report.Verify(envelope, trusted)
		if err != nil {
			// Refused, not counted. An aggregate that includes rows nobody signed is a
			// report about an attacker's imagination.
			unattributed++
			continue
		}
		if !cutoff.IsZero() && event.At.Before(cutoff) {
			continue
		}

		item := machines[event.Machine]
		if item == nil {
			item = &machine{name: event.Machine, byKind: map[report.Kind]int{}}
			machines[event.Machine] = item
		}
		item.byKind[event.Kind]++
		if event.At.After(item.last) {
			item.last = event.At
		}
		if event.Kind == report.KindRevoked || event.Kind == report.KindRestored {
			item.highlights = append(item.highlights, *event)
		}
	}

	if len(machines) == 0 {
		fmt.Printf("no signed events in %s\n", directory)
		if unattributed > 0 {
			fmt.Printf("%d file%s could not be attributed to a machine you trust\n",
				unattributed, plural(unattributed, "", "s"))
			return exitFindings
		}
		return exitClean
	}

	names := make([]string, 0, len(machines))
	for name := range machines {
		names = append(names, name)
	}
	sort.Strings(names)

	outstanding := 0
	for _, name := range names {
		item := machines[name]
		fmt.Printf("%s\n", name)
		fmt.Printf("  %-16s %s\n", "last report", item.last.Format(time.RFC3339))
		for _, kind := range []report.Kind{
			report.KindRevoked, report.KindRestored,
			report.KindUnverifiable, report.KindCatalogUnusable,
		} {
			if count := item.byKind[kind]; count > 0 {
				fmt.Printf("  %-16s %d\n", kind, count)
				outstanding += count
			}
		}
		sort.Slice(item.highlights, func(i, j int) bool {
			return item.highlights[i].At.After(item.highlights[j].At)
		})
		for index, event := range item.highlights {
			if index >= 3 {
				fmt.Printf("    … %d more\n", len(item.highlights)-3)
				break
			}
			fmt.Printf("    %s  %s\n", event.At.Format("01-02 15:04"), event.Summary())
		}
		fmt.Println()
	}

	fmt.Printf("%d machine%s reporting · %d event%s\n",
		len(names), plural(len(names), "", "s"),
		outstanding, plural(outstanding, "", "s"))
	if unattributed > 0 {
		fmt.Printf("%d file%s refused: not signed by a machine in %s\n",
			unattributed, plural(unattributed, "", "s"), *trustedPath)
	}
	if outstanding > 0 || unattributed > 0 {
		return exitFindings
	}
	return exitClean
}
