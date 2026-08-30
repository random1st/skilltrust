package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/random1st/skilltrust/internal/marketplace"
)

// runHookSessionStart reconciles signed plugins as a session begins.
//
// Three properties make it safe to run automatically, and each is a decision:
//
// It does not touch the network. A session must not wait on a fetch to a server behind a VPN
// that is not up yet; a hook that adds seconds to every session start is a hook that gets
// removed. It works from the marketplace already on disk, which still catches the case that
// matters most — a plugin edited on this machine — and still enforces every revocation the
// machine has been told about. Refreshing is `skillctl sync`.
//
// It says nothing when nothing changed. A hook that speaks every session is one people stop
// reading, and this one has to be read on the day it matters.
//
// It takes a lock. Two sessions opening together would otherwise both restore the same
// plugin, with the loser renaming a directory the winner had already moved.
func runHookSessionStart(args []string) int {
	flags := flag.NewFlagSet("hook session-start", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(),
			"Usage: skillctl hook session-start [flags]\n\n"+
				"Restores any signed plugin that was changed on this machine, and reports it.\n"+
				"Offline: it uses the marketplaces already fetched. Prints nothing when\n"+
				"nothing changed.\n\n"+
				"Exit code: %d always. A session-start hook cannot refuse anything, and\n"+
				"pretending otherwise would misdescribe what this is.\n\nFlags:\n", exitClean)
		flags.PrintDefaults()
	}

	claudeHome := flags.String("claude-home", "", "Claude Code directory (default ~/.claude)")
	verbose := flags.Bool("verbose", false, "also report when everything already matched")
	fetch := flags.Bool("fetch", false, "refresh first; adds network latency to the session")

	if err := parseArgs(flags, args); err != nil {
		return exitClean
	}
	home := *claudeHome
	if home == "" {
		home = marketplace.DefaultClaudeHome()
	}

	subscriptions, err := loadSubscriptions()
	if err != nil || len(subscriptions) == 0 {
		return exitClean // this machine follows no signed marketplace
	}

	release, held := takeLock()
	if !held {
		return exitClean // another session is already reconciling
	}
	defer release()

	results, unusable, code := reconcileAll(home, true, !*fetch)
	if code != exitClean {
		return exitClean
	}
	recordEvents(results, unusable, time.Now().UTC())
	for _, line := range pruneDeadAdoptions(results) {
		fmt.Printf("skillctl: %s\n", line)
	}
	writeSessionReport(results, unusable, *verbose)
	return exitClean
}

func writeSessionReport(results []marketplace.Result, unusable []string, verbose bool) {
	// An unusable marketplace is reported even though nothing was done, because "we could
	// not check" and "nothing had changed" produce the same silence and only one of them is
	// safe to read as fine.
	for _, failure := range unusable {
		fmt.Printf("skillctl: a signed marketplace could not be used, so its plugins were "+
			"not checked\n  %s\n  refresh with: skillctl sync\n\n", failure)
	}

	spoken, overridden := 0, 0
	for _, result := range results {
		if result.Outcome.Settled() {
			continue
		}
		if spoken == 0 {
			fmt.Printf("skillctl: your organisation's plugins were reconciled\n\n")
		}
		spoken++
		if result.Outcome != marketplace.OutcomeAdapted {
			overridden++
		}

		fmt.Printf("  %-13s %s   (%s)\n", result.Outcome, result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Printf("                %s\n", result.Detail)
		}
		if result.Outcome == marketplace.OutcomeRestored {
			fmt.Printf("                this copy had been changed here and was put back\n")
			fmt.Printf("                to keep your version instead: "+
				"skillctl adopt %s --from-quarantine --because \"...\"\n", result.Plugin)
		}
		// The reason lives in Adapted, not Detail, so a surface that only prints Detail
		// shows a divergence with no account of it — which is the state adopting exists to
		// replace. This is the third place that renders an outcome; the fix belongs in all
		// of them, not in whichever one was open at the time.
		if result.Outcome == marketplace.OutcomeAdapted && result.Adapted != "" {
			fmt.Printf("                your own copy, kept on purpose: %s\n", result.Adapted)
		}
		if result.Quarantine != "" {
			fmt.Printf("                what was there: %s\n", result.Quarantine)
		}
	}

	// The trailer is only true of plugins the check overrode. Printing it after a run
	// whose only news was "your own copy, kept on purpose" told the person their change
	// did not survive in the same breath as preserving it.
	if overridden > 0 {
		fmt.Printf("\nThese plugins are managed centrally; local changes to them do not survive.\n")
		return
	}
	if spoken > 0 {
		return
	}
	if verbose && len(unusable) == 0 {
		fmt.Printf("skillctl: %d signed plugin%s unchanged\n",
			len(results), plural(len(results), "", "s"))
	}
}

// takeLock serializes reconciliation between concurrently opening sessions.
//
// Failing to take it is not an error and is not reported: the other holder is doing the same
// work, so the right behaviour is to let it, quietly. A lock older than its timeout is broken
// rather than honoured, because a crashed session must not disable the check on this machine
// forever — that would be a silent off switch anyone could arrange.
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
