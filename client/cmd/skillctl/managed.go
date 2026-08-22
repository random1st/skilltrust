package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/catalog"
	"github.com/random1st/skilltrust/client/internal/fleet"
	"github.com/random1st/skilltrust/client/internal/source"
)

// CatalogFileName is the signed index a catalog repository publishes at its root.
const CatalogFileName = "catalog.dsse.json"

// Subscription is one catalog this machine follows.
//
// The key is pinned at subscribe time and never learned from the catalog itself. A catalog
// that could introduce its own signing key could replace itself, which would make the
// signature a formality rather than a check.
type Subscription struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Ref        string `json:"ref,omitempty"`
	KeyID      string `json:"key_id"`
}

func subscriptionsPath() string { return homePath("catalogs.json") }

func loadSubscriptions() ([]Subscription, error) {
	raw, err := os.ReadFile(subscriptionsPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var subscriptions []Subscription
	if err := json.Unmarshal(raw, &subscriptions); err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", subscriptionsPath(), err)
	}
	return subscriptions, nil
}

func saveSubscriptions(subscriptions []Subscription) error {
	sort.Slice(subscriptions, func(i, j int) bool { return subscriptions[i].Name < subscriptions[j].Name })
	body, err := json.MarshalIndent(subscriptions, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(subscriptionsPath(), append(body, '\n'), 0o600)
}

func runSubscribe(args []string) int {
	flags := flag.NewFlagSet("subscribe", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl subscribe [flags] <git-url>\n\n"+
			"Follows an organisation's skill catalog. The publisher's key is pinned now,\n"+
			"from a file you already trust; it is never taken from the catalog itself.\n\n"+
			"Exit codes: %d subscribed, %d error.\n\nFlags:\n", exitClean, exitUsage)
		flags.PrintDefaults()
	}

	name := flags.String("name", "", "short name for this catalog (default the repository name)")
	ref := flags.String("ref", "", "branch or tag to follow (default the repository's HEAD)")
	keyPath := flags.String("key", "", "PEM public key of the catalog publisher (required)")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 || *keyPath == "" {
		flags.Usage()
		return exitUsage
	}

	repository := flags.Arg(0)
	catalogName := *name
	if catalogName == "" {
		catalogName = source.NameFor(repository)
	}

	public, err := attest.LoadPublicKey(*keyPath)
	if err != nil {
		return fail(err)
	}
	keyID := attest.KeyID(public)

	if err := attest.PinKey(defaultTrustedKeys(), "catalog:"+catalogName, public); err != nil {
		return fail(err)
	}

	fetched, err := source.Fetch(catalogRoot(), catalogName, repository, *ref)
	if err != nil {
		return fail(err)
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return fail(err)
	}
	replaced := false
	for index, existing := range subscriptions {
		if existing.Name == catalogName {
			subscriptions[index] = Subscription{catalogName, repository, *ref, keyID}
			replaced = true
		}
	}
	if !replaced {
		subscriptions = append(subscriptions,
			Subscription{catalogName, repository, *ref, keyID})
	}
	if err := saveSubscriptions(subscriptions); err != nil {
		return fail(err)
	}

	fmt.Printf("catalog     %s\n", catalogName)
	fmt.Printf("repository  %s @ %s\n", repository, shortCommit(fetched.Commit))
	fmt.Printf("pinned key  %s\n\n", attest.Fingerprint(keyID))
	fmt.Printf("Next: skillctl sync --dry-run   — see what this catalog would change\n")
	return exitClean
}

// catalogRoot is where catalog checkouts live, kept apart from anything the user edits.
func catalogRoot() string { return Home() }

func quarantineRoot() string { return homePath("quarantine") }

func statePath(catalogName string) string {
	return filepath.Join(Home(), "state", catalogName+".json")
}

// runSync brings every managed skill back to what its catalog publishes.
func runSync(args []string) int {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl sync [flags]\n\n"+
			"Fetches every catalog you follow, verifies its signature, and reconciles the\n"+
			"skills it manages. A managed skill that was changed here is put back and the\n"+
			"copy that was there is kept. Nothing outside a catalog is touched.\n\n"+
			"Exit codes: %d nothing to do, %d something changed, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	into := flags.String("into", "", "skills directory to manage (default ~/.agents/skills)")
	dryRun := flags.Bool("dry-run", false, "report what would happen and change nothing")
	offline := flags.Bool("offline", false, "use the catalogs already fetched, without network")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return fail(err)
	}
	if len(subscriptions) == 0 {
		fmt.Fprintf(os.Stderr, "skillctl: no catalogs followed; subscribe to one with "+
			"`skillctl subscribe <git-url> --key <publisher.pub>`\n")
		return exitUsage
	}

	installRoot, err := installRoot(*into)
	if err != nil {
		return fail(err)
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return fail(err)
	}

	now := time.Now().UTC()
	var all []fleet.Change
	for _, subscription := range subscriptions {
		changes, code := syncOne(subscription, trusted, installRoot, now, *dryRun, *offline)
		if code != exitClean {
			return code
		}
		all = append(all, changes...)
	}

	return reportSync(all, installRoot, *dryRun)
}

// fetchCatalog refreshes one catalog checkout from its repository.
func fetchCatalog(subscription Subscription) (source.Source, error) {
	return source.Fetch(catalogRoot(), subscription.Name,
		subscription.Repository, subscription.Ref)
}

// verifiedSnapshot loads the index from a catalog checkout and returns it only if every
// check passes: signature, payload type, schema version, freshness, rollback resistance, and
// that the signer is the key pinned for this catalog specifically.
//
// The last one is easy to leave out and expensive to leave out. Verifying against the whole
// trusted set would let any publisher this machine trusts sign an index claiming another
// organisation's skill names, and the machine would install their bytes under those names.
func verifiedSnapshot(
	subscription Subscription, trusted *attest.TrustedKeys, now time.Time,
) (*catalog.Snapshot, error) {
	checkout := source.Path(catalogRoot(), subscription.Name)
	envelope, err := attest.LoadEnvelope(filepath.Join(checkout, CatalogFileName))
	if err != nil {
		return nil, fmt.Errorf("no usable %s: %w", CatalogFileName, err)
	}

	sequenceState, err := catalog.LoadState(statePath(subscription.Name + ".sequence"))
	if err != nil {
		return nil, err
	}
	snapshot, keyID, err := catalog.Verify(envelope, trusted, sequenceState, now)
	if err != nil {
		return nil, err
	}
	if keyID != subscription.KeyID {
		return nil, fmt.Errorf("signed by %s but subscribed with %s",
			attest.Fingerprint(keyID), attest.Fingerprint(subscription.KeyID))
	}
	if err := sequenceState.Save(
		statePath(subscription.Name+".sequence"), snapshot.Sequence, now); err != nil {
		return nil, err
	}
	if snapshot.Name == "" {
		snapshot.Name = subscription.Name
	}
	return snapshot, nil
}

func syncOne(
	subscription Subscription, trusted *attest.TrustedKeys, installRoot string,
	now time.Time, dryRun, offline bool,
) ([]fleet.Change, int) {
	if !offline {
		if _, err := fetchCatalog(subscription); err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: cannot reach catalog %s: %v\n",
				subscription.Name, err)
			return nil, exitUsage
		}
	}

	snapshot, err := verifiedSnapshot(subscription, trusted, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: catalog %s did not verify, so nothing was "+
			"changed: %v\n", subscription.Name, err)
		return nil, exitUsage
	}

	state, err := fleet.LoadState(statePath(subscription.Name))
	if err != nil {
		return nil, fail(err)
	}

	changes, err := fleet.Reconcile(snapshot, state, fleet.Options{
		SourceRoot:     source.Path(catalogRoot(), subscription.Name),
		InstallRoot:    installRoot,
		QuarantineRoot: quarantineRoot(),
		DryRun:         dryRun,
		Now:            now,
	})
	if err != nil {
		return nil, fail(err)
	}

	if !dryRun {
		state.Catalog, state.Sequence = subscription.Name, snapshot.Sequence
		if err := state.Save(statePath(subscription.Name)); err != nil {
			return nil, fail(err)
		}
	}
	return changes, exitClean
}

func reportSync(changes []fleet.Change, installRoot string, dryRun bool) int {
	acted, failed := 0, 0
	for _, change := range changes {
		if !change.Needed() {
			continue
		}
		acted++
		if change.Action == fleet.ActionFailed {
			failed++
		}
		fmt.Printf("  %-11s %s\n", change.Action, change.Name)
		if change.Reason != "" {
			fmt.Printf("              %s\n", change.Reason)
		}
		if change.Action == fleet.ActionRolledBack {
			fmt.Printf("              this copy had been changed on this machine\n")
			fmt.Printf("              restored  %s\n", change.Now)
			fmt.Printf("              was       %s\n", change.Was)
		}
		if change.Quarantine != "" {
			fmt.Printf("              kept at   %s\n", change.Quarantine)
		}
		fmt.Println()
	}

	fmt.Printf("%d managed skill%s · %d changed", len(changes),
		plural(len(changes), "", "s"), acted)
	if failed > 0 {
		fmt.Printf(" · %d failed", failed)
	}
	fmt.Printf("\nmanaged under %s; everything else there is yours and was not touched.\n",
		installRoot)

	if dryRun && acted > 0 {
		fmt.Printf("\nNothing was changed. Run without --dry-run to apply.\n")
	}
	if failed > 0 {
		return exitFindings
	}
	if acted > 0 {
		return exitFindings
	}
	return exitClean
}
