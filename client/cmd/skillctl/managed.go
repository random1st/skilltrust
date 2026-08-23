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

// shortCommit renders a commit for a person rather than for git.
func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// fetchCatalog refreshes one marketplace checkout from its repository.
func fetchCatalog(subscription Subscription) (source.Source, error) {
	return source.Fetch(catalogRoot(), subscription.Name,
		subscription.Repository, subscription.Ref)
}

// readSnapshot loads a marketplace signature and returns it only if every check passes:
// signature, payload type, schema version, freshness, rollback resistance, and that the
// signer is the key pinned for this marketplace specifically.
//
// The last one is easy to leave out and expensive to leave out. Verifying against the whole
// trusted set would let any publisher this machine trusts sign an index claiming another
// organisation's plugin names, and the machine would then treat their bytes as authoritative
// for those names.
//
// persist records the sequence that was seen, which is what makes rollback resistance work.
// It belongs where a marketplace is adopted and must not happen on a path that runs before
// every skill invocation: that would write a file on the critical path hundreds of times a
// session, and a check that only reads would start deciding what later checks may see.
func readSnapshot(
	subscription Subscription, trusted *attest.TrustedKeys, now time.Time, persist bool,
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
	if persist {
		if err := sequenceState.Save(
			statePath(subscription.Name+".sequence"), snapshot.Sequence, now); err != nil {
			return nil, err
		}
	}
	if snapshot.Name == "" {
		snapshot.Name = subscription.Name
	}
	return snapshot, nil
}

// readSnapshotOnly verifies without recording the sequence it saw.
func readSnapshotOnly(
	subscription Subscription, trusted *attest.TrustedKeys, now time.Time,
) (*catalog.Snapshot, error) {
	return readSnapshot(subscription, trusted, now, false)
}
