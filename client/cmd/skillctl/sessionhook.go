package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/fleet"
	"github.com/random1st/skilltrust/client/internal/source"
)

// runHookSessionStart reconciles managed skills as a session begins.
//
// Three properties make this safe to run automatically, and each is a decision:
//
// It does not touch the network. A session must not wait on a git fetch to a server that
// may be slow, unreachable, or behind a VPN the user has not connected yet; a hook that
// adds seconds to every session start is a hook that gets removed. It reconciles against
// the catalog already on disk, which still catches the case that matters most — a managed
// skill edited on this machine — and still enforces every revocation the machine has
// already been told about. Refreshing is `skillctl sync`, which a person runs or a timer
// does, not something the session waits for.
//
// It says nothing when nothing changed. A hook that speaks every session is one people stop
// reading, and this one has to be read on the day it matters.
//
// It takes a lock. Two sessions opening at once would otherwise both try to restore the same
// skill, and the loser would be renaming a directory the winner had already moved.
func runHookSessionStart(args []string) int {
	flags := flag.NewFlagSet("hook session-start", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(),
			"Usage: skillctl hook session-start [flags]\n\n"+
				"Restores any centrally managed skill that was changed on this machine, and\n"+
				"reports what it did. Offline: it uses the catalog already fetched. Prints\n"+
				"nothing when nothing changed.\n\n"+
				"Exit code: %d always. A session-start hook cannot refuse anything, and\n"+
				"pretending otherwise would misdescribe what this is.\n\nFlags:\n", exitClean)
		flags.PrintDefaults()
	}

	into := flags.String("into", "", "skills directory to manage (default ~/.agents/skills)")
	verbose := flags.Bool("verbose", false, "also report when everything already matched")
	fetch := flags.Bool("fetch", false, "refresh the catalogs first; adds network latency to the session")

	if err := parseArgs(flags, args); err != nil {
		return exitClean
	}

	subscriptions, err := loadSubscriptions()
	if err != nil || len(subscriptions) == 0 {
		// A machine that follows no catalog is not managed, and a hook that announces that
		// every session is noise about a state that is not going to change.
		if err != nil && *verbose {
			fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		}
		return exitClean
	}

	release, held := takeLock()
	if !held {
		return exitClean // another session is already reconciling
	}
	defer release()

	installRoot, err := installRoot(*into)
	if err != nil {
		return report(err)
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return report(err)
	}

	now := time.Now().UTC()
	var changes []fleet.Change
	var unusable []string

	for _, subscription := range subscriptions {
		if *fetch {
			refresh(subscription)
		}
		result, err := reconcileSubscription(subscription, trusted, installRoot, now)
		if err != nil {
			unusable = append(unusable, fmt.Sprintf("%s: %v", subscription.Name, err))
			continue
		}
		changes = append(changes, result...)
	}

	writeSessionReport(changes, unusable, *verbose)
	return exitClean
}

// reconcileSubscription runs one catalog against the machine, using only what is on disk.
func reconcileSubscription(
	subscription Subscription, trusted *attest.TrustedKeys, installRoot string, now time.Time,
) ([]fleet.Change, error) {
	snapshot, err := verifiedSnapshot(subscription, trusted, now)
	if err != nil {
		return nil, err
	}

	state, err := fleet.LoadState(statePath(subscription.Name))
	if err != nil {
		return nil, err
	}
	changes, err := fleet.Reconcile(snapshot, state, fleet.Options{
		SourceRoot:     source.Path(catalogRoot(), subscription.Name),
		InstallRoot:    installRoot,
		QuarantineRoot: quarantineRoot(),
		Now:            now,
	})
	if err != nil {
		return nil, err
	}
	state.Catalog, state.Sequence = subscription.Name, snapshot.Sequence
	if err := state.Save(statePath(subscription.Name)); err != nil {
		return nil, err
	}
	return changes, nil
}

func writeSessionReport(changes []fleet.Change, unusable []string, verbose bool) {
	// An unusable catalog is reported even though nothing was done, because "we could not
	// check" and "nothing had changed" produce the same silence and only one of them is
	// safe to read as fine. An expired catalog on a laptop that has been offline for a week
	// is the ordinary cause, and the remedy is in the message.
	for _, failure := range unusable {
		fmt.Printf("skillctl: a managed catalog could not be used, so its skills were not "+
			"checked\n  %s\n  refresh with: skillctl sync\n\n", failure)
	}

	acted := 0
	for _, change := range changes {
		if !change.Needed() {
			continue
		}
		if acted == 0 {
			fmt.Printf("skillctl: your organisation's skills were reconciled\n\n")
		}
		acted++

		fmt.Printf("  %-11s %s", change.Action, change.Name)
		if change.Catalog != "" {
			fmt.Printf("   (%s)", change.Catalog)
		}
		fmt.Println()
		if change.Reason != "" {
			fmt.Printf("              %s\n", change.Reason)
		}
		if change.Action == fleet.ActionRolledBack {
			fmt.Printf("              this copy had been changed here and was put back\n")
		}
		if change.Quarantine != "" {
			fmt.Printf("              what was there: %s\n", change.Quarantine)
		}
	}

	if acted > 0 {
		fmt.Printf("\nThese skills are managed centrally; local changes to them do not survive.\n")
		return
	}
	if verbose && len(unusable) == 0 {
		fmt.Printf("skillctl: %d managed skill%s unchanged\n",
			len(changes), plural(len(changes), "", "s"))
	}
}

func refresh(subscription Subscription) {
	if _, err := fetchCatalog(subscription); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: could not refresh %s: %v\n", subscription.Name, err)
	}
}

// takeLock serializes reconciliation between concurrently opening sessions.
//
// Failing to take it is not an error and is not reported: the other holder is doing exactly
// the same work, so the right behaviour is to let it, quietly. A stale lock older than its
// timeout is broken rather than honoured, because a crashed session must not disable the
// check on this machine forever — which would be a silent off switch anyone could arrange.
func takeLock() (func(), bool) {
	path := homePath("reconcile.lock")
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return func() {}, false
	}

	const staleAfter = 2 * time.Minute
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > staleAfter {
		_ = os.Remove(path)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return func() {}, false
	}
	fmt.Fprintf(file, "%d\n", os.Getpid())
	file.Close()

	return func() { _ = os.Remove(path) }, true
}

func report(err error) int {
	fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
	return exitClean
}
