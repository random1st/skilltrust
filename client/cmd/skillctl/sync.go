package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
)

type ManagedCheckOptions struct {
	Restore       bool
	Offline       bool
	UpdateSource  bool
	RefreshBudget time.Duration
	// Additional client homes reuse public bytes but still authorize team reads.
	teamOnline bool
	// looseRoots reconciles the skill directories a client reads loose, instead of a plugin
	// cache. Empty is the plugin cache, which is what every caller but a loose-skills client
	// wants and what every caller wanted before one existed.
	looseRoots []marketplace.SkillRoot
}

type ManagedCatalogCheck struct {
	Name       string    `json:"name"`
	Sequence   int64     `json:"sequence,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitempty"`
	Refreshed  bool      `json:"refreshed,omitempty"`
	UsedCached bool      `json:"used_cached,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

type ManagedCheck struct {
	Scope           string                `json:"scope"`
	Coverage        string                `json:"coverage"`
	Complete        bool                  `json:"complete"`
	CheckedAt       time.Time             `json:"checked_at"`
	Catalogs        []ManagedCatalogCheck `json:"catalogs,omitempty"`
	Results         []marketplace.Result  `json:"results,omitempty"`
	Unusable        []string              `json:"unusable,omitempty"`
	teamAccessError error
}

func RunManagedCheck(claudeHome string, options ManagedCheckOptions) (ManagedCheck, int) {
	return runManagedCheckTo(claudeHome, options, os.Stdout, os.Stderr)
}

// Hook adapters route all presentation through writers so Claude receives one JSON
// object even when a key rotates or a local file cannot be read.
func runManagedCheckTo(claudeHome string, options ManagedCheckOptions, output, diagnostics io.Writer) (ManagedCheck, int) {
	now := time.Now().UTC()
	check := ManagedCheck{Scope: CheckScopeManaged, CheckedAt: now}
	failure := func(err error) (ManagedCheck, int) {
		fmt.Fprintf(diagnostics, "skillctl: %v\n", err)
		return check, exitUsage
	}

	// Defaulted here rather than at each call site. CacheRoot("") is the relative path
	// ./plugins/cache, so a caller that forgets looks in the working directory, finds
	// nothing, and reports every plugin as not installed — a wrong answer that reads
	// exactly like a correct one. One caller had already forgotten.
	if claudeHome == "" {
		claudeHome = marketplace.DefaultClaudeHome()
	}
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return failure(err)
	}
	if len(subscriptions) == 0 {
		check.Coverage = "empty"
		return check, exitClean
	}

	ctx, cancel := refreshContext(options.RefreshBudget)
	defer cancel()

	if !options.Offline {
		refreshed := false
		for i := range subscriptions {
			if subscriptions[i].CatalogURL == "" || subscriptions[i].Access != "" || legacyAxelaSubscription(subscriptions[i]) {
				continue
			}
			added, err := refreshSubscriptionContext(ctx, &subscriptions[i], defaultTrustedKeys(), now)
			if err != nil || len(added) == 0 {
				continue
			}
			refreshed = true
			fmt.Fprintf(output, "%-11s %s now also pinned for %s\n",
				"pinned", strings.Join(fingerprints(added), ", "), subscriptions[i].Name)
		}
		if refreshed {
			if err := saveSubscriptions(subscriptions); err != nil {
				return failure(err)
			}
		}
	}

	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return failure(err)
	}

	// A file this machine's owner wrote deliberately. An unreadable one adopts nothing and
	// is reported: the alternative direction — a corrupt file quietly meaning "accept every
	// difference here" — turns a local mistake into a silent hole.
	adopted, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil {
		fmt.Fprintf(diagnostics, "skillctl: %v\n"+
			"  Nothing is adopted this run, so every signed skill is checked as published.\n", err)
		adopted = marketplace.Adoptions{}
	}

	// One locator for the whole run. Which directories hold the copies is a property of the
	// client, not of any catalog, and building it here is what keeps the reconciler below
	// from ever asking which client it is serving.
	var locate marketplace.Locator
	if len(options.looseRoots) > 0 {
		locate = marketplace.LooseSkills(options.looseRoots)
	}

	for _, subscription := range subscriptions {
		snapshot, catalogCheck, err := loadManagedSnapshot(ctx, subscription, trusted, now, options)
		if err != nil {
			if subscription.Access != "" || legacyAxelaSubscription(subscription) {
				check.teamAccessError = err
			}
			check.Unusable = append(check.Unusable, fmt.Sprintf("%s: %v", subscription.Name, err))
			catalogCheck.Detail = err.Error()
			check.Catalogs = append(check.Catalogs, catalogCheck)
			continue
		}

		sourcePath := source.Path(catalogRoot(), subscription.Name)
		if subscription.Access == "team" {
			// The authenticated transaction already checked and promoted the exact
			// archive. It is never a Git checkout or an offline restore source.
		} else if options.UpdateSource && subscription.CatalogURL != "" {
			if _, err := fetchCatalogContext(ctx, subscription); err != nil {
				if catalogCheck.Refreshed {
					sourcePath = ""
				}
				appendManagedDetail(&catalogCheck, "source update failed: %v", err)
			}
		} else if subscription.CatalogURL != "" && catalogCheck.Refreshed {
			sourcePath = ""
			appendManagedDetail(&catalogCheck, "restore requires a full sync after catalog refresh")
		}

		// A curator that keeps its own record of what it changed is telling us which
		// differences are decisions. Reading it here, per catalog, is what stops an ordinary
		// curated host from reporting every skill it maintains as tampering.
		accepted := adopted
		if locate != nil {
			accepted = mergeAdoptions(adopted,
				curatorLedgerAdoptions(snapshot, options.looseRoots, locate))
		}

		check.Catalogs = append(check.Catalogs, catalogCheck)
		check.Results = append(check.Results, marketplace.Reconcile(snapshot, marketplace.Options{
			ClaudeHome:     claudeHome,
			Adopted:        accepted,
			Locate:         locate,
			Source:         sourcePath,
			QuarantineRoot: quarantineRoot(),
			Restore:        options.Restore,
			Now:            now,
		})...)
	}
	check.Coverage, check.Complete = managedCoverage(check.Results, check.Unusable)
	return check, exitClean
}

// reconcileAll runs every followed marketplace against this machine's plugin cache.
//
// One reconciler, one target. There were briefly two — a skills directory this tool invented
// and the plugin cache Claude Code actually loads from — and two answers to one question is
// how one of them ends up trusted and the other ignored. The cache won because it is where
// the bytes that run live; the invented directory was deleted.
func reconcileAll(claudeHome string, restore, offline bool) ([]marketplace.Result, []string, int) {
	check, code := RunManagedCheck(claudeHome, ManagedCheckOptions{
		Restore: restore, Offline: offline, UpdateSource: !offline,
	})
	return check.Results, check.Unusable, code
}

func refreshContext(budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), budget)
}

func loadManagedSnapshot(
	ctx context.Context,
	subscription Subscription,
	trusted *attest.TrustedKeys,
	now time.Time,
	options ManagedCheckOptions,
) (*catalog.Snapshot, ManagedCatalogCheck, error) {
	status := ManagedCatalogCheck{Name: subscription.Name}
	if subscription.Access != "" {
		if options.Offline && !options.teamOnline {
			return nil, status, fmt.Errorf("%s requires current team access; run %s doctor online before checking or restoring it. Existing files were kept", subscription.Name, commandName())
		}
		snapshot, _, err := refreshTeamSubscription(ctx, subscription, now)
		if err != nil {
			return nil, status, err
		}
		status.Sequence, status.ValidUntil, status.Refreshed = snapshot.Sequence, snapshot.ValidUntil, true
		return snapshot, status, nil
	}
	if legacyAxelaSubscription(subscription) {
		return nil, status, legacyAxelaUpgrade(subscription)
	}
	if options.Offline {
		snapshot, err := readSnapshot(subscription, trusted, now, !options.Offline)
		if err != nil {
			return nil, status, err
		}
		status.Sequence = snapshot.Sequence
		status.ValidUntil = snapshot.ValidUntil
		return snapshot, status, nil
	}
	if subscription.CatalogURL == "" {
		if options.UpdateSource {
			if _, err := fetchCatalogContext(ctx, subscription); err != nil {
				cached, cachedErr := readSnapshot(subscription, trusted, now, false)
				if cachedErr != nil {
					return nil, status, err
				}
				status.Sequence = cached.Sequence
				status.ValidUntil = cached.ValidUntil
				status.UsedCached = true
				status.Detail = fmt.Sprintf("using cached catalog after source update failed: %v", err)
				return cached, status, nil
			}
		}
		snapshot, err := readSnapshot(subscription, trusted, now, true)
		if err != nil {
			return nil, status, err
		}
		status.Sequence = snapshot.Sequence
		status.ValidUntil = snapshot.ValidUntil
		if options.UpdateSource {
			status.Refreshed = true
		}
		return snapshot, status, nil
	}

	snapshot, err := refreshCatalogSnapshot(ctx, subscription, trusted, now)
	if err == nil {
		status.Sequence = snapshot.Sequence
		status.ValidUntil = snapshot.ValidUntil
		status.Refreshed = true
		return snapshot, status, nil
	}

	cached, cachedErr := readSnapshot(subscription, trusted, now, false)
	if cachedErr != nil {
		return nil, status, err
	}
	status.Sequence = cached.Sequence
	status.ValidUntil = cached.ValidUntil
	status.UsedCached = true
	status.Detail = fmt.Sprintf("using cached catalog after refresh failed: %v", err)
	return cached, status, nil
}

func refreshCatalogSnapshot(
	ctx context.Context,
	subscription Subscription,
	trusted *attest.TrustedKeys,
	now time.Time,
) (*catalog.Snapshot, error) {
	target := indexPath(subscription)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return nil, err
	}
	staged, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".")
	if err != nil {
		return nil, err
	}
	stagePath := staged.Name()
	staged.Close()
	defer os.Remove(stagePath)

	if err := source.FetchIndexContext(ctx, subscription.CatalogURL, stagePath); err != nil {
		return nil, err
	}
	snapshot, err := readSnapshotPath(stagePath, subscription, trusted, now, false)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(stagePath, target); err != nil {
		return nil, err
	}
	if err := saveSnapshotSequence(subscription, snapshot.Sequence, now); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func managedCoverage(results []marketplace.Result, unusable []string) (string, bool) {
	if len(results) == 0 {
		return "empty", false
	}
	if len(unusable) > 0 {
		return "partial", false
	}
	for _, result := range results {
		if result.Outcome == marketplace.OutcomeUnverifiable {
			return "partial", false
		}
	}
	return "full", true
}

func appendManagedDetail(status *ManagedCatalogCheck, format string, arguments ...any) {
	addition := fmt.Sprintf(format, arguments...)
	if addition == "" {
		return
	}
	if status.Detail == "" {
		status.Detail = addition
		return
	}
	status.Detail += "; " + addition
}

// pruneDeadAdoptions drops adoption records that no longer describe anything on disk, and
// says so — once, at the moment they die.
//
// The reconciler never looks at an adoption once its plugin verifies as published: after
// an upstream version bump the new release installs, matches its signature, and the record
// sits in `adopt --list` looking alive for a decision that quietly stopped existing. The
// command's own promise is "the publisher ships a new version → checking resumes and says
// so"; this is the saying so.
func pruneDeadAdoptions(results []marketplace.Result) []string {
	adoptions, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil || len(adoptions.Entries) == 0 {
		return nil
	}
	var ended []string
	changed := false
	for _, result := range results {
		if result.Outcome != marketplace.OutcomeVerified {
			continue
		}
		entry, ok := adoptions.Find(result.Marketplace, result.Plugin)
		if !ok {
			continue
		}
		adoptions, _ = adoptions.Forget(result.Marketplace, result.Plugin)
		changed = true
		was := entry.Version
		if was == "" {
			was = "an earlier release"
		}
		ended = append(ended, fmt.Sprintf(
			"your adoption of %s ended: %s is installed exactly as published, so the "+
				"record was removed (it was for %s: %s)",
			result.Plugin, result.Version, was, entry.Reason))
	}
	if changed {
		if err := marketplace.SaveAdoptions(defaultAdoptions(), adoptions); err != nil {
			ended = append(ended, fmt.Sprintf("the ended records could not be removed: %v", err))
		}
	}
	return ended
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

	agentName := flags.String("agent", "claude", "which client's skills to check: claude, codex or hermes")
	claudeHome := flags.String("claude-home", "", "the client's directory (default the agent's own)")
	// The older name says Claude on a command that now checks four clients. Both are accepted
	// and neither is deprecated in output: renaming a flag people have in cron jobs and hooks
	// buys clarity for new readers by breaking machines that already work.
	clientHome := flags.String("home", "", "the client's directory (default the agent's own)")
	offline := flags.Bool("offline", false, "use the marketplaces already fetched")
	report := flags.Bool("report-only", false, "say what differs without putting anything back")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if *claudeHome != "" && *clientHome != "" && *claudeHome != *clientHome {
		fmt.Fprintln(os.Stderr, "skillctl: --home and --claude-home name the same thing and "+
			"were given different directories; pass one")
		return exitUsage
	}
	if *claudeHome == "" {
		*claudeHome = *clientHome
	}
	home, err := resolveAgentHome(*agentName, *claudeHome)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	// Where the copies live is decided once, from the client's table entry and the home in
	// front of us. A loose-skills client with no readable root is not a machine with nothing
	// installed — it is a machine this run cannot describe — so it says so rather than
	// printing a clean report about directories it never opened.
	var looseRoots []marketplace.SkillRoot
	if known, err := lookupAgent(*agentName); err == nil && known.Layout == layoutLooseSkills {
		looseRoots = looseSkillRoots(known, home)
		if len(looseRoots) == 0 {
			fmt.Fprintf(os.Stderr, "skillctl: no skill directory found for %s under %s; "+
				"nothing here could be checked\n", known.Name, home)
			return exitUsage
		}
	}

	if subscriptions, err := loadSubscriptions(); err == nil && len(subscriptions) == 0 {
		fmt.Fprintln(os.Stderr, "skillctl: no marketplaces followed; subscribe with "+
			"`skillctl subscribe <git-url> --key <publisher.pub>`")
		return exitUsage
	}

	managed, code := RunManagedCheck(home, ManagedCheckOptions{
		Restore: !*report, Offline: *offline, UpdateSource: !*offline, looseRoots: looseRoots,
	})
	if code != exitClean {
		return code
	}

	var loose LooseSkillCheck
	var drift []skillDrift
	looseCode := exitClean
	// An explicit client directory is an isolated scope, including in the demo.
	// Do not discover loose skills in the caller's actual project or home.
	if *claudeHome == "" {
		roots, err := optionalSkillRoots(baseDirectories())
		if err != nil {
			return fail(err)
		}
		if len(roots) > 0 {
			trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
			if err != nil {
				return fail(err)
			}
			loose, drift, looseCode = verifySkillRootsReporting(trusted, true, roots)
		}
	}
	reportManaged := managed
	if known, err := lookupAgent(*agentName); err == nil && known.Managed {
		reportManaged = aggregateManagedReportCheck(managed, home, *agentName, *claudeHome)
	}

	now := time.Now().UTC()
	events := collectEvents(managed.Results, managed.Unusable, now)
	events = append(events, skillDriftEvents(drift, now)...)
	checks := []CurrentCheck{managedCurrentCheck(reportManaged)}
	if shouldReportLooseSkillCheck(loose) {
		checks = append(checks, looseSkillCurrentCheck(loose))
	}
	_, _ = recordReports(events, checks, 2*time.Second)

	if !*report {
		for _, line := range pruneDeadAdoptions(managed.Results) {
			fmt.Printf("  %s\n", line)
		}
	}
	code = writeReconcileReport(managed.Results, managed.Unusable, home, *report,
		checkedRoots(looseRoots)...)
	if looseCode != exitClean {
		fmt.Fprintln(os.Stderr, "skillctl: local skills outside the plugin cache need attention; run skillctl attest verify for details")
		if code == exitClean {
			return looseCode
		}
	}
	return code
}

// checkedRoots names the directories a loose-skills run actually read, for the line that
// tells a person where the check happened. Empty for a plugin-cache client, whose one tree
// the report can name by itself.
func checkedRoots(roots []marketplace.SkillRoot) []string {
	paths := make([]string, 0, len(roots))
	for _, root := range roots {
		paths = append(paths, root.Path)
	}
	return paths
}

// reportedName is how one result is addressed in a report: the skill, prefixed by the copy it
// belongs to when there is more than one. "aws-readonly" on a host with three profiles names
// three different files, and a person cannot act on a line that does not say which.
func reportedName(result marketplace.Result) string {
	if result.Copy == "" {
		return result.Plugin
	}
	return result.Copy + "/" + result.Plugin
}

// writeReconcileReport prints what a reconciliation found.
//
// checkedIn names the directories that were read, and is given only by a client whose skills
// do not live in a plugin cache. It is variadic because every caller that had nothing to say
// about it was already correct, and making them all pass an empty argument would be churn in
// exchange for nothing.
func writeReconcileReport(
	results []marketplace.Result, unusable []string, claudeHome string, reportOnly bool,
	checkedIn ...string,
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
		if result.Outcome != marketplace.OutcomeRestored && result.Outcome != marketplace.OutcomeAdapted {
			unresolved++
		}

		fmt.Printf("  %-13s %s   (%s)\n", result.Outcome, reportedName(result), result.Marketplace)
		if result.Detail != "" {
			fmt.Printf("                %s\n", result.Detail)
		}
		switch result.Outcome {
		case marketplace.OutcomeRestored:
			fmt.Printf("                this copy had been changed here and was put back\n")
		case marketplace.OutcomeAdapted:
			// The reason is the whole reason to print this line. Without it a person
			// reading their own machine six months on sees a divergence and no account
			// of it, which is the state adopting was supposed to replace.
			fmt.Printf("                your own copy, kept on purpose: %s\n", result.Adapted)
		case marketplace.OutcomeChanged:
			fmt.Printf("                signed  %s\n", result.Signed)
			fmt.Printf("                on disk %s\n", result.OnDisk)
		case marketplace.OutcomeOtherVersion:
			fmt.Printf("                %s is signed, %s is installed\n",
				result.Version, result.Installed)
		}
		if result.Quarantine != "" {
			fmt.Printf("                kept at %q\n", result.Quarantine)
			if result.ClientHome == "" {
				// This argument is the actual checked cache root, never a guessed client.
				result.ClientHome = claudeHome
			}
			writeQuarantineNotice(os.Stdout, result)
		}
	}

	verified, absent, restored, adapted := 0, 0, 0, 0
	for _, result := range results {
		switch result.Outcome {
		case marketplace.OutcomeVerified:
			verified++
		case marketplace.OutcomeAbsent:
			absent++
		case marketplace.OutcomeRestored:
			restored++
		case marketplace.OutcomeAdapted:
			adapted++
		}
	}
	if acted > 0 {
		fmt.Println()
	}
	// Completed actions get their own counts. Restoring a plugin is not an unresolved
	// finding, and it is not a subsequent clean verification either.
	fmt.Printf("%d signed plugin%s · %d verified · %d not installed here",
		len(results), plural(len(results), "", "s"), verified, absent)
	if restored > 0 {
		fmt.Printf(" · %d restored", restored)
	}
	if adapted > 0 {
		fmt.Printf(" · %d kept by choice", adapted)
	}
	fmt.Printf(" · %d needing attention\n", unresolved)
	where := marketplace.CacheRoot(claudeHome)
	if len(checkedIn) > 0 {
		where = strings.Join(checkedIn, ", ")
	}
	fmt.Printf("checked in %s; anything unsigned there is not this tool's business.\n", where)

	// And said in words when the count alone would still be read as reassurance. This is the
	// same failure the note below describes for an unreadable marketplace — a run that
	// verified nothing looking exactly like a run where nothing was wrong — and it was fixed
	// there and missed here.
	if verified == 0 && acted == 0 && absent > 0 {
		fmt.Printf("\nNothing was verified: none of these is installed on this machine. "+
			"That is fine if you did not expect them here, and is the whole finding if you did.\n"+
			"Install one from its marketplace, or check you are following the right catalog: "+
			"%s\n", subscriptionsPath())
	}

	// A marketplace that could not be read contributes zero to every count above, so the
	// summary of a failed run reads exactly like the summary of a clean one — and it is
	// the last thing on screen, which is the part people actually read. The failure is
	// already on stderr; this puts it back under the numbers it invalidates, because a
	// tool built on refusing to overstate what it verified cannot overstate its own run.
	if len(unusable) > 0 {
		fmt.Printf("\n%d marketplace%s could not be read, and nothing above covers %s. "+
			"These plugins were not checked at all.\n",
			len(unusable), plural(len(unusable), "", "s"), plural(len(unusable), "it", "them"))
	}

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
