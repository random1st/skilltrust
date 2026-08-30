package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/internal/marketplace"
)

func runAdopt(args []string) int {
	flags := flag.NewFlagSet("adopt", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl adopt [flags] <plugin>\n\n"+
			"Keeps a change you made to a signed skill, instead of having it put back.\n\n"+
			"Editing a skill to suit your setup is ordinary, and without this the check\n"+
			"treats it as tampering: your copy goes to quarantine and the published one\n"+
			"returns, every session. Adopting records that these exact bytes are yours.\n\n"+
			"It is not an off switch. The record names the bytes you adopted and the\n"+
			"version you adopted them from, so if the file changes again, or the publisher\n"+
			"ships a new version, checking resumes and says so. Your machine reports an\n"+
			"adopted plugin like any other finding.\n\n"+
			"  skillctl adopt deploy-runbook --because \"our staging URL, not theirs\"\n"+
			"  skillctl adopt deploy-runbook --from-quarantine --because \"...\"\n"+
			"                                            # take back a change a check put back\n"+
			"  skillctl adopt deploy-runbook --forget    # go back to the published copy\n"+
			"  skillctl adopt --list\n\n"+
			"Exit codes: %d done, %d nothing matched, %d usage error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}
	because := flags.String("because", "",
		"why you changed it — required, and kept with the record")
	marketplaceName := flags.String("marketplace", "",
		"which catalog the plugin belongs to, when two publish the same name")
	forget := flags.Bool("forget", false,
		"drop the record, so the published copy is restored on the next check")
	fromQuarantine := flags.Bool("from-quarantine", false,
		"put the newest quarantined copy of the plugin back first, then adopt it — "+
			"the way to keep a change a check has already put back")
	list := flags.Bool("list", false, "print what this machine has adopted")
	claudeHome := flags.String("claude-home", "", "Claude Code directory (default ~/.claude)")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
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
	if strings.TrimSpace(*because) == "" {
		fmt.Fprintf(os.Stderr, "skillctl: say why, so the record is worth reading later:\n"+
			"  skillctl adopt %s --because \"what you changed and why\"\n", name)
		return exitUsage
	}

	home := *claudeHome

	// The digests come from the same reconciliation sync runs, not from a second reading
	// of the tree. Two ways of computing an identity is how one of them ends up quietly
	// wrong, and here it would record an adoption that never matches anything.
	results, _, code := reconcileAll(home, false, true)
	if code == exitUsage {
		return code
	}

	if *fromQuarantine {
		if code := reclaimFromQuarantine(results, home, *marketplaceName, name); code != exitClean {
			return code
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
		if errors.Is(err, errAlreadyPublished) && !*fromQuarantine {
			if _, ok := newestQuarantine(name); ok {
				fmt.Fprintf(os.Stderr, "  an earlier copy of it is in quarantine; to take "+
					"that back and keep it:\n  skillctl adopt %s --from-quarantine --because %q\n",
					name, *because)
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
	quarantined, ok := newestQuarantine(plugin)
	if !ok {
		fmt.Fprintf(os.Stderr, "skillctl: nothing quarantined for %s in %s\n",
			plugin, quarantineRoot())
		return exitFindings
	}
	installed := marketplace.InstalledPath(claudeHome, found.Marketplace, plugin, found.Version)
	if err := marketplace.Reclaim(quarantined, installed); err != nil {
		return fail(err)
	}
	fmt.Printf("%-11s %s, from %s\n", "took back", plugin, quarantined)
	return exitClean
}

// newestQuarantine finds the most recent quarantined copy of a plugin. The directory names
// embed a UTC timestamp, so the lexicographically last one is the latest.
func newestQuarantine(plugin string) (string, bool) {
	entries, err := os.ReadDir(quarantineRoot())
	if err != nil {
		return "", false
	}
	prefix := plugin + "-"
	best := ""
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		// The suffix must look like a timestamp, or the quarantined copy of a plugin named
		// "run" would claim everything quarantined for "run-tests".
		rest := entry.Name()[len(prefix):]
		if len(rest) < 8 || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		if entry.Name() > best {
			best = entry.Name()
		}
	}
	if best == "" {
		return "", false
	}
	return filepath.Join(quarantineRoot(), best), true
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
