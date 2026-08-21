package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		anyPinned                     bool
	)

	for _, root := range roots {
		report := lint.Run(root, lint.Options{})
		counts := report.Counts()
		total += len(report.Skills)
		high += counts[lint.SeverityHigh]
		medium += counts[lint.SeverityMedium]
		low += counts[lint.SeverityLow]

		lockPath := filepath.Join(root, lockfile.FileName)
		if lock, err := lockfile.Load(lockPath); err == nil {
			anyPinned = true
			drift := lockfile.Verify(root, lockPath, lock, lint.Options{})
			driftedCount += drift.Drifted()
			// Count what the lock records, not what verify reported on: a skill present
			// but unpinned appears in the results and is precisely not pinned.
			pinned += len(lock.Skills)
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr,
				"skillctl: a lock could not be read, so drift is unknown: %v\n", err)
			return exitUsage
		}

		records, err := receipt.LoadAll(root)
		if err != nil {
			return fail(err)
		}
		held += len(records)
		for _, record := range records {
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
		fmt.Printf("  drift        not pinned — run `skillctl lock`\n")
	case driftedCount == 0:
		fmt.Printf("  drift        none · %d pinned\n", pinned)
	default:
		fmt.Printf("  drift        %d changed since they were pinned\n", driftedCount)
	}

	fmt.Printf("  approvals    %d approved · %d unapproved · %d unmanaged\n",
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
