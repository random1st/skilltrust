package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
)

// reconcileAll runs every followed marketplace against this machine's plugin cache.
//
// One reconciler, one target. There were briefly two — a skills directory this tool invented
// and the plugin cache Claude Code actually loads from — and two answers to one question is
// how one of them ends up trusted and the other ignored. The cache won because it is where
// the bytes that run live; the invented directory was deleted.
func reconcileAll(claudeHome string, restore, offline bool) ([]marketplace.Result, []string, int) {
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return nil, nil, fail(err)
	}
	if len(subscriptions) == 0 {
		return nil, nil, exitClean
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return nil, nil, fail(err)
	}

	now := time.Now().UTC()
	var results []marketplace.Result
	var unusable []string

	for _, subscription := range subscriptions {
		if !offline {
			if _, err := fetchCatalog(subscription); err != nil {
				unusable = append(unusable,
					fmt.Sprintf("%s could not be reached: %v", subscription.Name, err))
				continue
			}
			// The notary's index and the repository's bytes are both required: the index
			// alone can detect but not restore, and restoring from bytes the fresh index
			// no longer names would fail the digest check anyway. Refusing on either
			// failure keeps "checked" meaning checked.
			if subscription.CatalogURL != "" {
				if err := source.FetchIndex(subscription.CatalogURL, indexPath(subscription)); err != nil {
					unusable = append(unusable,
						fmt.Sprintf("%s: %v", subscription.Name, err))
					continue
				}
			}
		}
		snapshot, err := readSnapshot(subscription, trusted, now, !offline)
		if err != nil {
			unusable = append(unusable, fmt.Sprintf("%s: %v", subscription.Name, err))
			continue
		}
		results = append(results, marketplace.Reconcile(snapshot, marketplace.Options{
			ClaudeHome:     claudeHome,
			Source:         source.Path(catalogRoot(), subscription.Name),
			QuarantineRoot: quarantineRoot(),
			Restore:        restore,
			Now:            now,
		})...)
	}
	return results, unusable, exitClean
}

func runSync(args []string) int {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl sync [flags]\n\n"+
			"Fetches every marketplace you follow, verifies its signature, and checks the\n"+
			"plugins Claude Code installed from it. A plugin changed on this machine is put\n"+
			"back and the copy that was there is kept. Nothing unsigned is touched.\n\n"+
			"Exit codes: %d nothing to do, %d something changed, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	claudeHome := flags.String("claude-home", "", "Claude Code directory (default ~/.claude)")
	offline := flags.Bool("offline", false, "use the marketplaces already fetched")
	report := flags.Bool("report-only", false, "say what differs without putting anything back")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	home := *claudeHome
	if home == "" {
		home = marketplace.DefaultClaudeHome()
	}

	if subscriptions, err := loadSubscriptions(); err == nil && len(subscriptions) == 0 {
		fmt.Fprintln(os.Stderr, "skillctl: no marketplaces followed; subscribe with "+
			"`skillctl subscribe <git-url> --key <publisher.pub>`")
		return exitUsage
	}

	results, unusable, code := reconcileAll(home, !*report, *offline)
	if code != exitClean {
		return code
	}
	if !*report {
		recordEvents(results, unusable, time.Now().UTC())
	}
	return writeReconcileReport(results, unusable, home, *report)
}

func writeReconcileReport(
	results []marketplace.Result, unusable []string, claudeHome string, reportOnly bool,
) int {
	for _, failure := range unusable {
		fmt.Fprintf(os.Stderr, "skillctl: a marketplace could not be used, so its plugins "+
			"were not checked\n  %s\n", failure)
	}

	acted, unresolved := 0, 0
	for _, result := range results {
		if result.Outcome.Settled() {
			continue
		}
		acted++
		if result.Outcome != marketplace.OutcomeRestored {
			unresolved++
		}

		fmt.Printf("  %-13s %s   (%s)\n", result.Outcome, result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Printf("                %s\n", result.Detail)
		}
		switch result.Outcome {
		case marketplace.OutcomeRestored:
			fmt.Printf("                this copy had been changed here and was put back\n")
			fmt.Printf("                was     %s\n", result.OnDisk)
		case marketplace.OutcomeChanged:
			fmt.Printf("                signed  %s\n", result.Signed)
			fmt.Printf("                on disk %s\n", result.OnDisk)
		case marketplace.OutcomeOtherVersion:
			fmt.Printf("                %s is signed, %s is installed\n",
				result.Version, result.Installed)
		}
		if result.Quarantine != "" {
			fmt.Printf("                kept at %s\n", result.Quarantine)
		}
	}

	verified := 0
	for _, result := range results {
		if result.Outcome == marketplace.OutcomeVerified {
			verified++
		}
	}
	if acted > 0 {
		fmt.Println()
	}
	fmt.Printf("%d signed plugin%s · %d verified · %d needing attention\n",
		len(results), plural(len(results), "", "s"), verified, acted)
	fmt.Printf("checked in %s; anything unsigned there is not this tool's business.\n",
		marketplace.CacheRoot(claudeHome))

	if reportOnly && acted > 0 {
		fmt.Printf("\nNothing was changed. Run without --report-only to put plugins back.\n")
	}
	if len(unusable) > 0 {
		return exitUsage
	}
	if acted > 0 {
		return exitFindings
	}
	return exitClean
}

var _ = catalog.SnapshotVersion
