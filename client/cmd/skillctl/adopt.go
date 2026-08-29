package main

import (
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
	found, err := pick(results, *marketplaceName, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitFindings
	}

	entry := marketplace.Adoption{
		Marketplace: found.Marketplace, Plugin: name,
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

// pick finds the one plugin being adopted, and refuses rather than guessing when the name
// is ambiguous or the copy on disk is not one an adoption can describe.
func pick(results []marketplace.Result, marketplaceName, plugin string) (marketplace.Result, error) {
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
		for _, match := range matches {
			names = append(names, match.Marketplace)
		}
		return marketplace.Result{}, fmt.Errorf(
			"%s is published by %s; say which with --marketplace",
			plugin, strings.Join(names, " and "))
	}

	found := matches[0]
	switch found.Outcome {
	case marketplace.OutcomeVerified:
		return marketplace.Result{}, fmt.Errorf(
			"%s already matches what was published, so there is nothing to adopt", plugin)
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

func printAdoptions(adoptions marketplace.Adoptions) int {
	if len(adoptions.Entries) == 0 {
		fmt.Println("nothing is adopted on this machine; every signed skill is checked as published")
		return exitClean
	}
	fmt.Printf("%-28s %-16s %s\n", "PLUGIN", "MARKETPLACE", "BECAUSE")
	for _, entry := range adoptions.Entries {
		fmt.Printf("%-28s %-16s %s\n", entry.Plugin, entry.Marketplace, entry.Reason)
	}
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

func short(digest string) string {
	if len(digest) > 26 {
		return digest[:26] + "…"
	}
	return digest
}
