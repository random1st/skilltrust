package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/fleet"
	"github.com/random1st/skilltrust/client/internal/source"
)

// runStatus answers "what is managed on this machine, by whom, and is it as published".
//
// It deliberately says nothing about skills no catalog claims. Reporting them would put a
// number on the screen that the tool has no business acting on, and every session would
// invite the reader to do something about skills that are theirs to write however they like.
func runStatus(args []string) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl status [flags]\n\n"+
			"What your organisation manages on this machine, and whether it matches.\n"+
			"Offline: it reads the catalogs already fetched.\n\n"+
			"Exit codes: %d as published, %d something differs, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	into := flags.String("into", "", "skills directory to inspect (default ~/.agents/skills)")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return fail(err)
	}
	installRoot, err := installRoot(*into)
	if err != nil {
		return fail(err)
	}

	fmt.Printf("%s\n\n", installRoot)
	if len(subscriptions) == 0 {
		fmt.Printf("  catalogs     none — this machine is not centrally managed\n\n")
		fmt.Printf("Follow one with: skillctl subscribe <git-url> --key <publisher.pub>\n")
		return exitClean
	}

	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return fail(err)
	}

	now := time.Now().UTC()
	differing, unusable := 0, 0

	for _, subscription := range subscriptions {
		snapshot, err := verifiedSnapshot(subscription, trusted, now)
		if err != nil {
			unusable++
			fmt.Printf("  %-12s unusable — %v\n", subscription.Name, err)
			fmt.Printf("  %-12s refresh with `skillctl sync`\n\n", "")
			continue
		}

		state, err := fleet.LoadState(statePath(subscription.Name))
		if err != nil {
			return fail(err)
		}
		// A dry run is how status stays a question rather than an action: it reports what
		// sync would do without doing it, so reading the state never changes it.
		changes, err := fleet.Reconcile(snapshot, state, fleet.Options{
			SourceRoot:     source.Path(catalogRoot(), subscription.Name),
			InstallRoot:    installRoot,
			QuarantineRoot: quarantineRoot(),
			DryRun:         true,
			Now:            now,
		})
		if err != nil {
			return fail(err)
		}

		pending := 0
		for _, change := range changes {
			if change.Needed() {
				pending++
			}
		}
		differing += pending

		fmt.Printf("  %-12s %d skill%s · catalog %d · valid until %s\n",
			subscription.Name, len(snapshot.Skills), plural(len(snapshot.Skills), "", "s"),
			snapshot.Sequence, snapshot.ValidUntil.Format("2006-01-02"))
		fmt.Printf("  %-12s %s\n", "", subscription.Repository)
		fmt.Printf("  %-12s signed by %s\n", "", attest.Fingerprint(subscription.KeyID))
		if len(snapshot.Revoked) > 0 {
			fmt.Printf("  %-12s %d revoked digest%s\n", "",
				len(snapshot.Revoked), plural(len(snapshot.Revoked), "", "s"))
		}

		if pending == 0 {
			fmt.Printf("  %-12s as published\n\n", "")
			continue
		}
		fmt.Println()
		for _, change := range changes {
			if !change.Needed() {
				continue
			}
			fmt.Printf("    %-11s %s\n", change.Action, change.Name)
		}
		fmt.Println()
	}

	if unusable > 0 {
		fmt.Printf("Next: skillctl sync   — %d catalog%s could not be read\n",
			unusable, plural(unusable, "", "s"))
		return exitUsage
	}
	if differing > 0 {
		fmt.Printf("Next: skillctl sync   — %d managed skill%s differ from what is published\n",
			differing, plural(differing, "", "s"))
		return exitFindings
	}
	fmt.Printf("Everything your organisation manages is as published.\n")
	return exitClean
}

// installRoot is the directory the agent reads and the only one this tool writes into.
func installRoot(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agents", "skills"), nil
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
