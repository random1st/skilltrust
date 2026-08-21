package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/catalog"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
	"github.com/random1st/skilltrust/client/internal/receipt"
)

// runStatus answers "what is my situation" in one screen.
//
// Everything here can be had from lint, verify, sync and receipts, but only by knowing
// which four commands to run and how to hold their answers together. The complexity of
// having four separate checks belongs under the hood; a person opening a terminal wants
// one number per question.
func runStatus(args []string) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl status [flags] [path]\n\n"+
			"One screen: what is installed, what changed, what is approved, what is revoked.\n\n"+
			"Exit codes: %d clean, %d something needs attention, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	roots, err := resolveSkillRoots(flags.Arg(0))
	if err != nil {
		return fail(err)
	}

	var snapshot *catalog.Snapshot
	if info, err := os.Stat(defaultCatalog()); err == nil && info.Mode().IsRegular() {
		trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
		if err != nil {
			return fail(err)
		}
		envelope, err := attest.LoadEnvelope(defaultCatalog())
		if err != nil {
			return fail(err)
		}
		state, err := catalog.LoadState(catalog.DefaultStatePath(defaultCatalog()))
		if err != nil {
			return fail(err)
		}
		snapshot, _, err = catalog.Verify(envelope, trusted, state, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"skillctl: the catalog is unusable, so revocation is unknown: %v\n", err)
			return exitUsage
		}
	}

	var (
		total, high, medium, low      int
		approved, unapproved, held    int
		revoked, pinned, driftedCount int
		notarized                     int
		anyPinned                     bool
	)

	for _, root := range roots {
		report := lint.Run(root, lint.Options{})
		counts := report.Counts()
		total += len(report.Skills)
		high += counts[lint.SeverityHigh]
		medium += counts[lint.SeverityMedium]
		low += counts[lint.SeverityLow]

		// Every record is optional here — signed approvals, a lock, install receipts — and
		// verify reads all three, so status asks it once rather than keeping a second
		// opinion of its own about what "recorded" means.
		records, notes, err := loadRecords(root)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"skillctl: a record could not be read, so drift is unknown: %v\n", err)
			return exitUsage
		}

		drift := lockfile.Verify(root, records, lint.Options{})
		if unchecked := append(notes, drift.Unchecked...); len(unchecked) > 0 {
			for _, note := range unchecked {
				fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
			}
			return exitUsage
		}
		driftedCount += drift.Drifted()
		for _, result := range drift.Results {
			if result.PinnedBy == lockfile.PinnedByNotarization {
				notarized++
			}
		}
		// Count what was recorded, not everything verify looked at: a skill present but
		// never recorded appears in the results and is precisely the opposite of pinned.
		recorded := len(drift.Results) - drift.Unpinned()
		pinned += recorded
		anyPinned = anyPinned || recorded > 0

		receipts, err := receipt.LoadAll(root)
		if err != nil {
			return fail(err)
		}
		held += len(receipts)
		for _, record := range receipts {
			if record.Approval == nil {
				unapproved++
			} else {
				approved++
			}
		}

		if snapshot != nil {
			directories, _ := lint.Discover(root, lint.Options{})
			for _, directory := range directories {
				built, err := archive.Build(directory, archive.Limits{})
				if err != nil {
					continue
				}
				if _, hit := snapshot.IsRevoked(built.Digest); hit {
					revoked++
				}
			}
		}
	}

	unmanaged := total - held

	for _, root := range roots {
		fmt.Printf("%s\n", root)
	}
	fmt.Println()
	fmt.Printf("  skills       %d\n", total)
	fmt.Printf("  findings     %d high · %d medium · %d low\n", high, medium, low)

	switch {
	case !anyPinned:
		fmt.Printf("  drift        nothing recorded — run `skillctl lock`\n")
	case driftedCount == 0:
		fmt.Printf("  drift        none · %d recorded\n", pinned)
	default:
		fmt.Printf("  drift        %d changed since they were recorded\n", driftedCount)
	}

	// Notarization is reported apart from install approvals because it answers a different
	// question: not "did this arrive with an approval" but "is there a signature over the
	// bytes that are here now".
	if notarized == 0 {
		fmt.Printf("  notarized    none — run `skillctl setup` to sign these\n")
	} else {
		fmt.Printf("  notarized    %d of %d signed\n", notarized, total)
	}
	fmt.Printf("  installs     %d approved · %d unapproved · %d unmanaged\n",
		approved, unapproved, unmanaged)

	if snapshot == nil {
		fmt.Printf("  revocation   no catalog — not checked\n")
	} else {
		fmt.Printf("  revocation   %d revoked · catalog %d valid until %s\n",
			revoked, snapshot.Sequence, snapshot.ValidUntil.Format("2006-01-02"))
	}

	fmt.Println()
	problems := high + revoked + driftedCount

	switch {
	case problems > 0:
		fmt.Println("Next: skillctl verify   (what changed)   ·   skillctl lint   (what is in them)")
		return exitFindings
	case !anyPinned:
		fmt.Println("Next: skillctl lock     — pin these, so a later change is detectable")
		return exitClean
	default:
		fmt.Println("Nothing needs attention.")
		return exitClean
	}
}
