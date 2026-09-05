package main

import (
	"context"
	"flag"
	"fmt"
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
	Scope     string                `json:"scope"`
	Coverage  string                `json:"coverage"`
	Complete  bool                  `json:"complete"`
	CheckedAt time.Time             `json:"checked_at"`
	Catalogs  []ManagedCatalogCheck `json:"catalogs,omitempty"`
	Results   []marketplace.Result  `json:"results,omitempty"`
	Unusable  []string              `json:"unusable,omitempty"`
}

func RunManagedCheck(claudeHome string, options ManagedCheckOptions) (ManagedCheck, int) {
	now := time.Now().UTC()
	check := ManagedCheck{Scope: CheckScopeManaged, CheckedAt: now}

	// Defaulted here rather than at each call site. CacheRoot("") is the relative path
	// ./plugins/cache, so a caller that forgets looks in the working directory, finds
	// nothing, and reports every plugin as not installed — a wrong answer that reads
	// exactly like a correct one. One caller had already forgotten.
	if claudeHome == "" {
		claudeHome = marketplace.DefaultClaudeHome()
	}
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return check, fail(err)
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
			if subscriptions[i].CatalogURL == "" {
				continue
			}
			added, err := refreshSubscriptionContext(ctx, &subscriptions[i], defaultTrustedKeys(), now)
			if err != nil || len(added) == 0 {
				continue
			}
			refreshed = true
			fmt.Printf("%-11s %s now also pinned for %s\n",
				"pinned", strings.Join(fingerprints(added), ", "), subscriptions[i].Name)
		}
		if refreshed {
			if err := saveSubscriptions(subscriptions); err != nil {
				return check, fail(err)
			}
		}
	}

	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return check, fail(err)
	}

	// A file this machine's owner wrote deliberately. An unreadable one adopts nothing and
	// is reported: the alternative direction — a corrupt file quietly meaning "accept every
	// difference here" — turns a local mistake into a silent hole.
	adopted, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n"+
			"  Nothing is adopted this run, so every signed skill is checked as published.\n", err)
		adopted = marketplace.Adoptions{}
	}

	for _, subscription := range subscriptions {
		snapshot, catalogCheck, err := loadManagedSnapshot(ctx, subscription, trusted, now, options)
		if err != nil {
			check.Unusable = append(check.Unusable, fmt.Sprintf("%s: %v", subscription.Name, err))
			catalogCheck.Detail = err.Error()
			check.Catalogs = append(check.Catalogs, catalogCheck)
			continue
		}

		sourcePath := source.Path(catalogRoot(), subscription.Name)
		if options.UpdateSource && subscription.CatalogURL != "" {
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

		check.Catalogs = append(check.Catalogs, catalogCheck)
		check.Results = append(check.Results, marketplace.Reconcile(snapshot, marketplace.Options{
			ClaudeHome:     claudeHome,
			Adopted:        adopted,
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

	agentName := flags.String("agent", "claude", "which client's plugins to check: claude or codex")
	claudeHome := flags.String("claude-home", "", "the client's directory (default the agent's own)")
	offline := flags.Bool("offline", false, "use the marketplaces already fetched")
	report := flags.Bool("report-only", false, "say what differs without putting anything back")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	home, err := resolveAgentHome(*agentName, *claudeHome)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	if subscriptions, err := loadSubscriptions(); err == nil && len(subscriptions) == 0 {
		fmt.Fprintln(os.Stderr, "skillctl: no marketplaces followed; subscribe with "+
			"`skillctl subscribe <git-url> --key <publisher.pub>`")
		return exitUsage
	}

	managed, code := RunManagedCheck(home, ManagedCheckOptions{
		Restore: !*report, Offline: *offline, UpdateSource: !*offline,
	})
	if code != exitClean {
		return code
	}

	var loose LooseSkillCheck
	var drift []skillDrift
	if trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys()); err == nil {
		loose, drift, _ = verifyEverySkillReporting(trusted, true)
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
	return writeReconcileReport(managed.Results, managed.Unusable, home, *report)
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
		if result.Outcome != marketplace.OutcomeRestored && result.Outcome != marketplace.OutcomeAdapted {
			unresolved++
		}

		fmt.Printf("  %-13s %s   (%s)\n", result.Outcome, result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Printf("                %s\n", result.Detail)
		}
		switch result.Outcome {
		case marketplace.OutcomeRestored:
			if result.Lapsed {
				// Their copy is already in quarantine, so "adopt this" would adopt the
				// publisher's bytes - the opposite of what they want. The detail above
				// has already said what happened; all that helps here is the diff.
				break
			}
			fmt.Printf("                this copy had been changed here and was put back\n")
			// --from-quarantine, not a plain adopt: the restore above has already happened,
			// so the person's bytes are in quarantine and adopting what is installed now
			// would adopt the published copy — a hint that fails for everyone who takes it.
			fmt.Printf("                to keep your version instead: "+
				"skillctl adopt %s --from-quarantine --because \"...\"\n", result.Plugin)
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
			fmt.Printf("                kept at %s\n", result.Quarantine)
			// Both versions are on disk and nobody would guess the second path. Without
			// this line, re-applying a patch across an upstream release is archaeology:
			// find the quarantine directory, work out where the new copy landed, and
			// diff them by hand. It is the difference between a chore and a paste.
			fmt.Printf("                see what changed: diff -ru %s %s\n",
				result.Quarantine,
				marketplace.InstalledPath(claudeHome, result.Marketplace, result.Plugin, result.Version))
		}
	}

	verified, absent := 0, 0
	for _, result := range results {
		switch result.Outcome {
		case marketplace.OutcomeVerified:
			verified++
		case marketplace.OutcomeAbsent:
			absent++
		}
	}
	if acted > 0 {
		fmt.Println()
	}
	// Absent is counted out loud so the three numbers add up to the first one. They did not
	// before: a machine following catalogs that sign sixteen plugins, none of them installed
	// here, was told "16 signed plugins · 0 verified · 0 needing attention" — every figure
	// correct, and the whole line read as a clean verification of sixteen things.
	fmt.Printf("%d signed plugin%s · %d verified · %d not installed here · %d needing attention\n",
		len(results), plural(len(results), "", "s"), verified, absent, acted)
	fmt.Printf("checked in %s; anything unsigned there is not this tool's business.\n",
		marketplace.CacheRoot(claudeHome))

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
