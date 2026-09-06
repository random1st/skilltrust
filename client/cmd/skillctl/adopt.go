package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/random1st/skilltrust/internal/marketplace"
)

func runAdopt(args []string) int {
	flags := flag.NewFlagSet("adopt", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s adopt [flags] <plugin>\n\n"+
			"Keep an intentional local change to a signed skill. If a check already put\n"+
			"the published version back, diff reviews your saved copy and prints the\n"+
			"exact command to recover it.\n\n"+
			"The record applies to these exact bytes and this published version. Another\n"+
			"edit or a publisher update resumes checking; adapted skills remain visible\n"+
			"in your machine's report.\n\n"+
			"  %s adopt deploy-runbook --because \"our staging URL\"\n"+
			"  %s diff deploy-runbook                  # review a saved change first\n"+
			"  %s adopt deploy-runbook --forget        # restore on the next check\n"+
			"  %s adopt --list\n\n"+
			"Exit codes: %d done, %d nothing matched, %d usage error.\n\nFlags:\n",
			commandName(), commandName(), commandName(), commandName(), commandName(), exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}
	because := flags.String("because", "",
		"why you changed it — required, and kept with the record")
	marketplaceName := flags.String("marketplace", "",
		"which catalog the plugin belongs to, when two publish the same name")
	forget := flags.Bool("forget", false,
		"drop the record, so the published copy is restored on the next check")
	fromQuarantine := flags.Bool("from-quarantine", false,
		"recover the newest saved copy for this installation (legacy; use diff to select reviewed bytes)")
	quarantined := flags.String("quarantine", "", "exact saved copy shown by diff")
	reviewedDigest := flags.String("quarantine-digest", "", "reviewed payload digest printed by diff (required with --quarantine)")
	list := flags.Bool("list", false, "print what this machine has adopted")
	claudeHome := flags.String("claude-home", "", "Claude Code directory (default ~/.claude)")

	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if (*fromQuarantine && *quarantined != "") || (*reviewedDigest != "" && *quarantined == "") ||
		((*list || *forget) && (*fromQuarantine || *quarantined != "")) {
		return fail(fmt.Errorf("use --quarantine with its reviewed --quarantine-digest, without --from-quarantine, --forget or --list"))
	}

	adoptions, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil {
		return fail(err)
	}

	if *list {
		return printAdoptions(adoptions)
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}
	name := flags.Arg(0)

	if *forget {
		updated, found := adoptions.Forget(resolveMarketplace(adoptions, *marketplaceName, name), name)
		if !found {
			fmt.Fprintf(os.Stderr, "skillctl: %s was not adopted on this machine\n", name)
			return exitFindings
		}
		if err := marketplace.SaveAdoptions(defaultAdoptions(), updated); err != nil {
			return fail(err)
		}
		fmt.Printf("%s is no longer adopted; the next check puts the published copy back\n", name)
		return exitClean
	}

	// The reason is required at the point of decision, not asked for later. An adoption
	// with no reason cannot be told apart from a mistake, and in a year cannot be told
	// apart from a decision nobody remembers making.
	if strings.TrimSpace(*because) == "" && (*quarantined == "" || *reviewedDigest != "") {
		fmt.Fprintf(os.Stderr, "skillctl: say why, so the record is worth reading later:\n"+
			"  skillctl adopt %s --because \"what you changed and why\"\n", name)
		return exitUsage
	}

	home, err := recoveryHome(*claudeHome)
	if err != nil {
		return fail(err)
	}

	// The digests come from the same reconciliation sync runs, not from a second reading
	// of the tree. Two ways of computing an identity is how one of them ends up quietly
	// wrong, and here it would record an adoption that never matches anything.
	results, _, code := reconcileAll(home, false, true)
	if code == exitUsage {
		return code
	}

	if *fromQuarantine || *quarantined != "" {
		var recoveryCode int
		if *quarantined != "" {
			recoveryCode = reclaimExactQuarantine(results, home, *marketplaceName, name, *quarantined, *reviewedDigest)
		} else {
			recoveryCode = reclaimFromQuarantine(results, home, *marketplaceName, name)
		}
		if recoveryCode != exitClean {
			return recoveryCode
		}
		// The tree just changed under the earlier reconciliation, so its digests describe
		// a directory that no longer exists. Recompute rather than adopt stale bytes.
		results, _, code = reconcileAll(home, false, true)
		if code == exitUsage {
			return code
		}
	}

	found, err := pick(results, *marketplaceName, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		// The refusal is correct and still a dead end: after a restore the bytes worth
		// adopting are in quarantine, and the person was sent here by a hint that did not
		// say so. Point at the door instead of just closing this one.
		if errors.Is(err, errAlreadyPublished) && !*fromQuarantine && *quarantined == "" {
			published, _ := match(results, *marketplaceName, name)
			installed := marketplace.InstalledPath(home, published.Marketplace, name, published.Version)
			if saved, ok, err := marketplace.NewestQuarantine(quarantineRoot(), installed, name); err != nil {
				fmt.Fprintf(os.Stderr, "  %v\n", err)
			} else if ok {
				published.ClientHome = home
				command, _ := quarantineCommands(published, saved, "", "")
				fmt.Fprintln(os.Stderr, "  an earlier copy is in quarantine; review it before taking it back:")
				printNextCommand(command)
			}
		}
		return exitFindings
	}

	entry := marketplace.Adoption{
		Marketplace: found.Marketplace, Plugin: name, Version: found.Version,
		From: found.Signed, Local: found.OnDisk,
		Since: time.Now().UTC(), Reason: strings.TrimSpace(*because),
	}
	if err := marketplace.SaveAdoptions(defaultAdoptions(), adoptions.Record(entry)); err != nil {
		return fail(err)
	}

	fmt.Printf("%-11s %s\n", "adopted", name)
	fmt.Printf("%-11s %s\n", "yours", short(entry.Local))
	if entry.From != "" {
		fmt.Printf("%-11s %s\n", "published", short(entry.From))
	}
	fmt.Printf("%-11s %s\n", "because", entry.Reason)
	fmt.Println("\nYour machine will keep these bytes and report them as adapted. If they " +
		"change again,\nor the publisher ships a new version, it starts checking this " +
		"plugin again and says so.")
	return exitClean
}

func reclaimExactQuarantine(
	results []marketplace.Result, home, marketplaceName, plugin, quarantined, reviewedDigest string,
) int {
	found, err := match(results, marketplaceName, plugin)
	if err != nil {
		return fail(err)
	}
	found.ClientHome = home
	installed := marketplace.InstalledPath(home, found.Marketplace, plugin, found.Version)
	selected, payload, err := marketplace.QuarantinePayload(quarantined, installed, plugin)
	if err != nil {
		return fail(err)
	}
	if reviewedDigest == "" {
		fmt.Println("Review this saved copy first; diff prints a command bound to its exact bytes.")
		command, _ := quarantineCommands(found, selected, "", "")
		printNextCommand(command)
		return exitFindings
	}
	if payload.Digest != reviewedDigest {
		return fail(fmt.Errorf("the saved copy changed since review; run diff again before adopting it"))
	}
	if found.Outcome != marketplace.OutcomeVerified {
		return fail(fmt.Errorf("installed %q is %s; preserve its current state before recovering another copy", plugin, found.Outcome))
	}
	if err := recoveryAllowed(found, payload.Digest); err != nil {
		return fail(err)
	}
	if err := marketplace.ReclaimVerified(selected, installed, plugin, reviewedDigest, found.Signed); err != nil {
		return fail(err)
	}
	fmt.Printf("took back   %q, from %q\n", plugin, selected)
	return exitClean
}

// errAlreadyPublished marks the one refusal that has a recovery: the installed copy
// matches the signature, so if the person's change exists at all, it is in quarantine.
var errAlreadyPublished = errors.New("already matches what was published")

// reclaimFromQuarantine puts the newest quarantined copy of a plugin back in place, so the
// ordinary adopt flow that follows can describe and record it.
func reclaimFromQuarantine(
	results []marketplace.Result, claudeHome, marketplaceName, plugin string,
) int {
	found, err := match(results, marketplaceName, plugin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitFindings
	}
	// Revocation outranks recovery for the same reason it outranks adoption: quarantine is
	// exactly where withdrawn bytes go, and a command that moves them back would be the
	// undo button for the one mechanism that must not have one.
	if found.Outcome == marketplace.OutcomeRevoked {
		fmt.Fprintf(os.Stderr, "skillctl: %s is revoked (%s); what is in quarantine "+
			"stays there\n", plugin, found.Detail)
		return exitFindings
	}
	if found.Outcome == marketplace.OutcomeAbsent || found.Outcome == marketplace.OutcomeOtherVersion {
		fmt.Fprintf(os.Stderr, "skillctl: %s %s is not installed here, so there is no "+
			"place to put a quarantined copy back\n", plugin, found.Version)
		return exitFindings
	}
	installed := marketplace.InstalledPath(claudeHome, found.Marketplace, plugin, found.Version)
	quarantined, ok, err := marketplace.NewestQuarantine(quarantineRoot(), installed, plugin)
	if err != nil {
		return fail(err)
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "skillctl: nothing quarantined for %s in %s\n",
			plugin, quarantineRoot())
		return exitFindings
	}
	_, payload, err := marketplace.QuarantinePayload(quarantined, installed, plugin)
	if err != nil {
		return fail(err)
	}
	return reclaimExactQuarantine(results, claudeHome, marketplaceName, plugin, quarantined, payload.Digest)
}

// pick finds the one plugin being adopted, and refuses rather than guessing when the name
// is ambiguous or the copy on disk is not one an adoption can describe.
func pick(results []marketplace.Result, marketplaceName, plugin string) (marketplace.Result, error) {
	found, err := match(results, marketplaceName, plugin)
	if err != nil {
		return marketplace.Result{}, err
	}
	switch found.Outcome {
	case marketplace.OutcomeVerified:
		return marketplace.Result{}, fmt.Errorf(
			"%s %w, so there is nothing to adopt", plugin, errAlreadyPublished)
	case marketplace.OutcomeRevoked:
		// Revocation is a statement about now and outranks a signature; it must outrank a
		// local preference too, or the one mechanism for withdrawing a bad skill becomes
		// optional on exactly the machines that edited it.
		return marketplace.Result{}, fmt.Errorf(
			"%s is revoked (%s) and cannot be adopted", plugin, found.Detail)
	case marketplace.OutcomeAbsent, marketplace.OutcomeOtherVersion:
		return marketplace.Result{}, fmt.Errorf(
			"%s is not installed here, so there are no bytes to adopt", plugin)
	case marketplace.OutcomeUnverifiable:
		return marketplace.Result{}, fmt.Errorf(
			"%s could not be read (%s), so nothing can be claimed about it", plugin, found.Detail)
	}
	return found, nil
}

// match finds the one result a plugin name refers to, refusing rather than guessing when
// the name matches nothing or more than one catalog publishes it.
func match(results []marketplace.Result, marketplaceName, plugin string) (marketplace.Result, error) {
	var matches []marketplace.Result
	for _, result := range results {
		if result.Plugin != plugin {
			continue
		}
		if marketplaceName != "" && result.Marketplace != marketplaceName {
			continue
		}
		matches = append(matches, result)
	}
	switch {
	case len(matches) == 0:
		return marketplace.Result{}, fmt.Errorf(
			"no signed plugin called %q is installed here; adopt only applies to skills a "+
				"catalog you follow publishes", plugin)
	case len(matches) > 1:
		var names []string
		for _, found := range matches {
			names = append(names, found.Marketplace)
		}
		return marketplace.Result{}, fmt.Errorf(
			"%s is published by %s; say which with --marketplace",
			plugin, strings.Join(names, " and "))
	}
	return matches[0], nil
}

func printAdoptions(adoptions marketplace.Adoptions) int {
	if len(adoptions.Entries) == 0 {
		fmt.Println("nothing is adopted on this machine; every signed skill is checked as published")
		return exitClean
	}
	fmt.Printf("%-26s %-14s %-10s %s\n", "PLUGIN", "MARKETPLACE", "ADOPTED", "BECAUSE")
	for _, entry := range adoptions.Entries {
		fmt.Printf("%-26s %-14s %-10s %s\n",
			entry.Plugin, entry.Marketplace, age(entry.Since, time.Now().UTC()), entry.Reason)
	}
	fmt.Println("\nThese never expire. One ends when you edit the file again, or the " +
		"publisher ships a new version.")
	return exitClean
}

// resolveMarketplace picks the catalog an adoption belongs to when the caller did not say.
func resolveMarketplace(adoptions marketplace.Adoptions, given, plugin string) string {
	if given != "" {
		return given
	}
	for _, entry := range adoptions.Entries {
		if entry.Plugin == plugin {
			return entry.Marketplace
		}
	}
	return ""
}

// age is how long ago a decision was made, in the roughest units that still answer the
// question a reader is actually asking: is this recent, or did somebody leave it here?
func age(since, now time.Time) string {
	if since.IsZero() {
		return "unknown"
	}
	days := int(now.Sub(since).Hours() / 24)
	switch {
	case days < 1:
		return "today"
	case days < 60:
		return fmt.Sprintf("%dd ago", days)
	default:
		return fmt.Sprintf("%dmo ago", days/30)
	}
}

func short(digest string) string {
	if len(digest) > 26 {
		return digest[:26] + "…"
	}
	return digest
}
