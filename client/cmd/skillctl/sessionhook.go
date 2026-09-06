package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
)

// runHookSessionStart reconciles signed plugins as a session begins.
//
// Three properties make it safe to run automatically, and each is a decision:
//
// It keeps the network on a short leash. A session may refresh signed catalogs first, because
// fresh revocations matter the moment they are published, but the whole refresh budget is
// three seconds and the local check still runs from the cache when the network is slow or
// gone. A hook that waits on a VPN forever is a hook people remove.
//
// It says nothing when nothing changed. A hook that speaks every session is one people stop
// reading, and this one has to be read on the day it matters.
//
// It takes a lock. Two sessions opening together would otherwise both restore the same
// plugin, with the loser renaming a directory the winner had already moved.
func runHookSessionStart(args []string) int {
	return runHookSessionStartTo(args, os.Stdout, os.Stderr)
}

func runHookSessionStartTo(args []string, output, diagnostics io.Writer) int {
	return runHookSessionStartForBases(args, output, diagnostics, baseDirectories())
}

func runHookSessionStartForBases(args []string, output, diagnostics io.Writer, bases []string) int {
	flags := flag.NewFlagSet("hook session-start", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(),
			"Usage: skillctl hook session-start [flags]\n\n"+
				"Refreshes signed catalogs briefly, falls back to the cached ones when\n"+
				"offline, restores any signed plugin that was changed on this machine,\n"+
				"and reports it. Prints nothing when nothing changed.\n\n"+
				"Exit code: %d always. A session-start hook cannot refuse anything, and\n"+
				"pretending otherwise would misdescribe what this is.\n\nFlags:\n", exitClean)
		flags.PrintDefaults()
	}

	agentName := flags.String("agent", "claude", "which client's plugins to check: claude or codex")
	claudeHome := flags.String("claude-home", "", "the client's directory (default the agent's own)")
	verbose := flags.Bool("verbose", false, "also report when everything already matched")
	fetch := flags.Bool("fetch", true, "refresh signed catalogs first; pass -fetch=false to stay fully offline")
	claudeJSON := flags.Bool("claude-json", false, "return a Claude Code user-visible warning as hook JSON")

	if err := parseArgs(flags, args); err != nil {
		if *claudeJSON {
			_ = writeClaudeHookJSON(output, "SessionStart", flagOutput.String())
		} else {
			fmt.Fprint(diagnostics, flagOutput.String())
		}
		return exitClean
	}
	if *claudeJSON {
		var notice bytes.Buffer
		original := output
		output, diagnostics = &notice, &notice
		defer func() { _ = writeClaudeHookJSON(original, "SessionStart", notice.String()) }()
	}
	now := time.Now().UTC()
	var events []report.Event
	var checks []CurrentCheck
	looseChecked := 0
	if trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys()); err == nil {
		if roots, err := optionalSkillRoots(bases); err != nil {
			fmt.Fprintf(diagnostics, "Axela: local skills could not be checked: %v\n", err)
			checks = append(checks, CurrentCheck{Scope: CheckScopeApprovedSkills, CheckedAt: now, Errors: 1})
		} else {
			skills, drift, _ := inspectSkillRoots(trusted, true, roots, output, diagnostics)
			looseChecked = skills.Checked
			if shouldReportLooseSkillCheck(skills) {
				checks = append(checks, looseSkillCurrentCheck(skills))
			}
			if *claudeJSON && (skills.Unapproved > 0 || skills.Errors > 0) {
				fmt.Fprintf(output, "Axela: local skills need attention: %d unapproved, %d errors. Run %s doctor.\n",
					skills.Unapproved, skills.Errors, commandName())
			}
			events = append(events, skillDriftEvents(drift, now)...)
		}
	} else if *claudeJSON {
		fmt.Fprintf(diagnostics, "Axela: local skills were not checked because pinned keys could not be read: %v\n", err)
	}

	managedRan := false
	managedChecked := 0
	var results []marketplace.Result
	var unusable []string

	// Reconciling reads <home>/plugins/cache, so a client that installs nothing from a
	// marketplace would produce an empty walk and the same silence as a clean machine. The
	// two must not look alike: "checked, nothing had changed" is safe to read as fine and
	// "there was never anything here to check" is a different sentence.
	if known, err := lookupAgent(*agentName); err == nil && known.Layout != layoutPluginCache {
		fmt.Fprintf(diagnostics, "skillctl: %s keeps no plugin cache, so there is nothing "+
			"here for a session start to reconcile\n", known.Name)
	} else if homes, err := managedSessionHomes(*agentName, *claudeHome); err != nil {
		// A hook that fails loudly at the start of every session is a hook people remove,
		// so this reports and stands aside rather than taking the session down with it.
		fmt.Fprintf(diagnostics, "skillctl: %v\n", err)
	} else if subscriptions, err := loadSubscriptions(); err != nil {
		fmt.Fprintf(diagnostics, "skillctl: %v\n", err)
	} else if len(subscriptions) > 0 {
		release, held := takeLock()
		if held {
			defer release()

			managed, code := runSessionManagedChecksTo(homes, *fetch, output, diagnostics)
			if code == exitClean {
				managedRan = true
				results, unusable = managed.Results, managed.Unusable
				managedChecked = managedCurrentCheck(managed).Checked
				events = append(events, collectEvents(results, unusable, now)...)
				checks = append(checks, managedCurrentCheck(managed))
				for _, line := range pruneDeadAdoptions(results) {
					fmt.Fprintf(output, "skillctl: %s\n", line)
				}
			}
		} else if *claudeJSON {
			fmt.Fprintf(diagnostics, "Axela: this session did not finish a check because another check is running. Run %s doctor.\n", commandName())
		}
	}

	if _, err := recordReports(events, checks, 2*time.Second); err != nil && *claudeJSON {
		fmt.Fprintf(diagnostics, "Axela: the check report could not be saved or delivered: %v\n", err)
	}
	if managedRan {
		writeSessionReportTo(output, results, unusable, *verbose)
	}
	if *claudeJSON && looseChecked == 0 && managedChecked == 0 {
		fmt.Fprintf(output, "Axela: no installed skill was verified in this session. Run %s doctor.\n", commandName())
	}
	return exitClean
}

func managedSessionHomes(agentName, explicitHome string) ([]string, error) {
	if explicitHome != "" {
		return []string{explicitHome}, nil
	}
	detected := detectManagedAgents()
	if len(detected) == 0 {
		home, err := resolveAgentHome(agentName, "")
		if err != nil {
			return nil, err
		}
		return []string{home}, nil
	}
	seen := map[string]bool{}
	homes := make([]string, 0, len(detected))
	for _, known := range detected {
		home := known.Home()
		if seen[home] {
			continue
		}
		seen[home] = true
		homes = append(homes, home)
	}
	return homes, nil
}

func runSessionManagedChecks(homes []string, fetch bool) (ManagedCheck, int) {
	return runSessionManagedChecksTo(homes, fetch, os.Stdout, os.Stderr)
}

func runSessionManagedChecksTo(homes []string, fetch bool, output, diagnostics io.Writer) (ManagedCheck, int) {
	options := ManagedCheckOptions{
		Restore: true, Offline: !fetch, UpdateSource: fetch, RefreshBudget: 3 * time.Second, teamOnline: true,
	}
	var combined ManagedCheck
	for i, home := range homes {
		managed, code := runManagedCheckTo(home, options, output, diagnostics)
		if code != exitClean {
			return managed, code
		}
		if i == 0 {
			combined = managed
		} else {
			combined = mergeManagedChecks(combined, managed)
		}
		options.Offline = true
		options.UpdateSource = false
		options.RefreshBudget = 3 * time.Second
	}
	if len(homes) == 0 {
		return ManagedCheck{
			Scope:     CheckScopeManaged,
			Coverage:  "empty",
			CheckedAt: time.Now().UTC(),
		}, exitClean
	}
	return combined, exitClean
}

func aggregateManagedReportCheck(
	managed ManagedCheck, primaryHome, agentName, explicitHome string,
) ManagedCheck {
	homes, err := managedSessionHomes(agentName, explicitHome)
	if err != nil {
		return mergeManagedChecks(managed, managedCheckFailure(err.Error()))
	}

	seen := map[string]bool{}
	if primaryHome != "" {
		seen[primaryHome] = true
	}

	combined := managed
	for _, home := range homes {
		if seen[home] {
			continue
		}
		seen[home] = true

		extra, code := RunManagedCheck(home, ManagedCheckOptions{
			Restore: false, Offline: true, UpdateSource: false, teamOnline: managed.teamAccessError == nil, RefreshBudget: 3 * time.Second,
		})
		if code != exitClean && len(extra.Unusable) == 0 {
			extra = managedCheckFailure(fmt.Sprintf("%s could not be checked", home))
		}
		combined = mergeManagedChecks(combined, extra)
	}
	return combined
}

func managedCheckFailure(detail string) ManagedCheck {
	check := ManagedCheck{
		Scope:     CheckScopeManaged,
		CheckedAt: time.Now().UTC(),
	}
	if detail != "" {
		check.Unusable = append(check.Unusable, detail)
	}
	check.Coverage, check.Complete = managedCoverage(check.Results, check.Unusable)
	return check
}

func mergeManagedChecks(left, right ManagedCheck) ManagedCheck {
	if left.CheckedAt.IsZero() {
		return right
	}
	out := left
	if right.CheckedAt.After(out.CheckedAt) {
		out.CheckedAt = right.CheckedAt
	}
	if out.Scope == "" {
		out.Scope = CheckScopeManaged
	}
	if out.Coverage == "" {
		out.Coverage = right.Coverage
	}
	if right.Coverage == "partial" || right.Coverage == "empty" && out.Coverage == "full" {
		out.Coverage = right.Coverage
	}
	out.Results = append(out.Results, right.Results...)
	for _, failure := range right.Unusable {
		if !containsString(out.Unusable, failure) {
			out.Unusable = append(out.Unusable, failure)
		}
	}
	for _, catalogCheck := range right.Catalogs {
		mergeManagedCatalogCheck(&out.Catalogs, catalogCheck)
	}
	out.Coverage, out.Complete = managedCoverage(out.Results, out.Unusable)
	return out
}

func mergeManagedCatalogCheck(merged *[]ManagedCatalogCheck, incoming ManagedCatalogCheck) {
	for i := range *merged {
		current := &(*merged)[i]
		if current.Name != incoming.Name {
			continue
		}
		current.Sequence = moreConservativeCatalogSequence(current.Sequence, incoming.Sequence)
		current.ValidUntil = earlierCatalogExpiry(current.ValidUntil, incoming.ValidUntil)
		current.Refreshed = current.Refreshed || incoming.Refreshed
		current.UsedCached = current.UsedCached || incoming.UsedCached
		if incoming.Detail != "" && incoming.Detail != current.Detail {
			appendManagedDetail(current, "%s", incoming.Detail)
		}
		return
	}
	*merged = append(*merged, incoming)
}

func moreConservativeCatalogSequence(current, incoming int64) int64 {
	switch {
	case current <= 0:
		return incoming
	case incoming <= 0:
		return current
	case incoming < current:
		return incoming
	default:
		return current
	}
}

func earlierCatalogExpiry(current, incoming time.Time) time.Time {
	switch {
	case current.IsZero():
		return incoming
	case incoming.IsZero():
		return current
	case incoming.Before(current):
		return incoming
	default:
		return current
	}
}

func containsString(haystack []string, needle string) bool {
	for _, one := range haystack {
		if one == needle {
			return true
		}
	}
	return false
}

func writeSessionReport(results []marketplace.Result, unusable []string, verbose bool) {
	writeSessionReportTo(os.Stdout, results, unusable, verbose)
}

func writeSessionReportTo(output io.Writer, results []marketplace.Result, unusable []string, verbose bool) {
	// An unusable marketplace is reported even though nothing was done, because "we could
	// not check" and "nothing had changed" produce the same silence and only one of them is
	// safe to read as fine.
	for _, failure := range unusable {
		fmt.Fprintf(output, "skillctl: a signed marketplace could not be used, so its plugins were "+
			"not checked\n  %s\n  refresh with: skillctl sync\n\n", failure)
	}

	spoken, overridden := 0, 0
	for _, result := range results {
		if result.Outcome.Settled() {
			continue
		}
		if spoken == 0 {
			fmt.Fprintf(output, "skillctl: your organisation's plugins were reconciled\n\n")
		}
		spoken++
		if result.Outcome != marketplace.OutcomeAdapted {
			overridden++
		}

		fmt.Fprintf(output, "  %-13s %s   (%s)\n", result.Outcome, result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Fprintf(output, "                %s\n", result.Detail)
		}
		if result.Outcome == marketplace.OutcomeRestored {
			fmt.Fprintf(output, "                this copy had been changed here and was put back\n")
			writeQuarantineNotice(output, result)
		}
		// The reason lives in Adapted, not Detail, so a surface that only prints Detail
		// shows a divergence with no account of it — which is the state adopting exists to
		// replace. This is the third place that renders an outcome; the fix belongs in all
		// of them, not in whichever one was open at the time.
		if result.Outcome == marketplace.OutcomeAdapted && result.Adapted != "" {
			fmt.Fprintf(output, "                your own copy, kept on purpose: %s\n", result.Adapted)
		}
		if result.Quarantine != "" {
			fmt.Fprintf(output, "                what was there: %q\n", result.Quarantine)
		}
	}

	// The trailer is only true of plugins the check overrode. Printing it after a run
	// whose only news was "your own copy, kept on purpose" told the person their change
	// did not survive in the same breath as preserving it.
	if overridden > 0 {
		fmt.Fprintf(output, "\nThese plugins are managed centrally; local changes to them do not survive in the installed copy. Preserved edits remain in quarantine until you choose what to keep.\n")
		return
	}
	if spoken > 0 {
		return
	}
	if verbose && len(unusable) == 0 {
		fmt.Fprintf(output, "skillctl: %d signed plugin%s unchanged\n",
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
