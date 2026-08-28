package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/source"
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
	// CatalogURL, when set, is where the signed index is fetched from instead of the
	// repository — a notary service that countersigns and serves the catalog. The
	// repository remains the source of the plugin bytes; splitting the two is what lets a
	// revocation reach machines on the notary's schedule rather than the publisher's next
	// push. The URL changes nothing about verification: the notary's signature counts only
	// if its key is pinned here, like any other signer.
	CatalogURL string `json:"catalog_url,omitempty"`
	// KeyID is the single pinned key of a subscription made before thresholds existed. It is
	// read but never written: KeyIDs is the field now, and dropping this would silently
	// unsubscribe every machine that already follows something.
	KeyID string `json:"key_id,omitempty"`
	// KeyIDs are the keys allowed to sign this marketplace's index.
	KeyIDs []string `json:"key_ids,omitempty"`
	// Threshold is how many distinct pinned keys must have signed. One is the default and is
	// enough to know the bytes are intact; more is what makes a single stolen key, or a CI
	// job that can reach one, insufficient to publish.
	//
	// The consumer sets it, never the publisher. A publisher whose key was stolen would
	// declare a threshold of one, so a threshold a catalog carries about itself protects
	// nobody.
	Threshold int `json:"threshold,omitempty"`
	// Parties groups key ids that belong to one signer, so a signer mid-rotation — two
	// keys, one owner — still counts once toward the threshold. Without this, pinning a
	// notary's current and next key at threshold two would let the notary's two
	// signatures alone reach the count and publish without the publisher, which is the
	// exact thing the threshold exists to prevent. A key in no party is its own party;
	// existing flat subscriptions therefore behave exactly as before. The map is a party
	// label to the ids it covers, and an id listed here is pinned whether or not it also
	// appears in KeyIDs.
	Parties map[string][]string `json:"parties,omitempty"`
}

// Keys returns every key allowed to sign for this subscription.
func (s Subscription) Keys() []string {
	keys := s.KeyIDs
	if len(keys) == 0 && s.KeyID != "" {
		keys = []string{s.KeyID}
	}
	if len(s.Parties) == 0 {
		return keys
	}
	seen := map[string]struct{}{}
	var all []string
	for _, key := range keys {
		if _, dup := seen[key]; !dup {
			seen[key] = struct{}{}
			all = append(all, key)
		}
	}
	for _, party := range sortedParties(s.Parties) {
		for _, key := range s.Parties[party] {
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				all = append(all, key)
			}
		}
	}
	return all
}

// Required is how many distinct signers must be present.
func (s Subscription) Required() int {
	if s.Threshold > 1 {
		return s.Threshold
	}
	return 1
}

// partyOf maps every pinned key id to the party it counts as. A key in no party counts
// as itself.
func (s Subscription) partyOf() map[string]string {
	owner := map[string]string{}
	for _, key := range s.Keys() {
		owner[key] = key
	}
	for party, keys := range s.Parties {
		for _, key := range keys {
			owner[key] = party
		}
	}
	return owner
}

// Satisfied reports whether the signers meet this subscription's requirement, and says
// what was missing when they do not. The threshold counts distinct parties, not distinct
// keys: two signatures from one signer's rotation pair agree on nothing that one of them
// did not already assert.
func (s Subscription) Satisfied(signers []string) error {
	owner := s.partyOf()
	matched := map[string]struct{}{}
	for _, signer := range signers {
		if party, ok := owner[signer]; ok {
			matched[party] = struct{}{}
		}
	}
	if len(matched) >= s.Required() {
		return nil
	}
	if len(matched) == 0 {
		return fmt.Errorf("signed by %s, none of which this machine pinned for %s",
			strings.Join(fingerprints(signers), ", "), s.Name)
	}
	return fmt.Errorf("%d of the %d signatures %s requires are present",
		len(matched), s.Required(), s.Name)
}

// sortedParties keeps every walk over the parties map deterministic, so files and error
// messages do not shuffle between runs.
func sortedParties(parties map[string][]string) []string {
	labels := make([]string, 0, len(parties))
	for label := range parties {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

func fingerprints(keys []string) []string {
	short := make([]string, 0, len(keys))
	for _, key := range keys {
		short = append(short, attest.Fingerprint(key))
	}
	return short
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
	catalogURL := flags.String("catalog", "",
		"HTTPS URL to fetch the signed index from (a notary service); the repository still provides the plugin bytes")
	var keyPaths repeatedString
	flags.Var(&keyPaths, "key",
		"PEM public key allowed to sign this marketplace (repeatable)")
	threshold := flags.Int("threshold", 1,
		"how many distinct pinned keys must have signed; more than one makes a single stolen key insufficient")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 || len(keyPaths) == 0 {
		flags.Usage()
		return exitUsage
	}
	if *threshold > len(keyPaths) {
		fmt.Fprintf(os.Stderr, "skillctl: --threshold %d needs at least that many --key "+
			"arguments; a requirement no set of keys can meet would refuse every index\n",
			*threshold)
		return exitUsage
	}

	repository := flags.Arg(0)
	catalogName := *name
	if catalogName == "" {
		catalogName = source.NameFor(repository)
	}

	var keyIDs []string
	for index, path := range keyPaths {
		public, err := attest.LoadPublicKey(path)
		if err != nil {
			return fail(err)
		}
		label := "catalog:" + catalogName
		if len(keyPaths) > 1 {
			label = fmt.Sprintf("%s:%d", label, index+1)
		}
		if err := attest.PinKey(defaultTrustedKeys(), label, public); err != nil {
			return fail(err)
		}
		keyIDs = append(keyIDs, attest.KeyID(public))
	}

	// A machine that follows a marketplace will file reports about it, and a key it does not
	// have yet turns the first real incident into "no machine key" instead of an alert.
	if _, _, created, err := ensureSigningKey(gitIdentity()); err != nil {
		return fail(err)
	} else if created {
		fmt.Printf("machine key %s\n", attest.Fingerprint(mustKeyID()))
	}

	fetched, err := source.Fetch(catalogRoot(), catalogName, repository, *ref)
	if err != nil {
		return fail(err)
	}

	entry := Subscription{
		Name: catalogName, Repository: repository, Ref: *ref, CatalogURL: *catalogURL,
		KeyIDs: keyIDs, Threshold: *threshold,
	}
	// Fetch the index now rather than at the first sync: a subscription to an unreachable
	// or misspelled notary should fail while the person who typed the URL is still looking
	// at it, not during a hook run days later.
	if entry.CatalogURL != "" {
		if err := source.FetchIndex(entry.CatalogURL, indexPath(entry)); err != nil {
			return fail(err)
		}
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return fail(err)
	}
	replaced := false
	for index, existing := range subscriptions {
		if existing.Name == catalogName {
			subscriptions[index] = entry
			replaced = true
		}
	}
	if !replaced {
		subscriptions = append(subscriptions, entry)
	}
	if err := saveSubscriptions(subscriptions); err != nil {
		return fail(err)
	}

	fmt.Printf("catalog     %s\n", catalogName)
	fmt.Printf("repository  %s @ %s\n", repository, shortCommit(fetched.Commit))
	if entry.CatalogURL != "" {
		fmt.Printf("index from  %s\n", entry.CatalogURL)
	}
	fmt.Printf("pinned keys %s\n", strings.Join(fingerprints(keyIDs), ", "))
	fmt.Printf("threshold   %d of %d must sign\n\n", *threshold, len(keyIDs))
	fmt.Printf("Next: skillctl sync --dry-run   — see what this catalog would change\n")
	return exitClean
}

// catalogRoot is where catalog checkouts live, kept apart from anything the user edits.
func catalogRoot() string { return Home() }

// indexPath is where a subscription's signed index lives.
//
// A subscription with a notary keeps its index outside the git checkout on purpose: the
// checkout is reset hard and cleaned on every fetch, which would silently discard a file
// this tool wrote into it, and the failure would surface as "no usable catalog.dsse.json"
// with nothing pointing at why.
func indexPath(subscription Subscription) string {
	if subscription.CatalogURL != "" {
		return filepath.Join(Home(), "indexes", subscription.Name+".dsse.json")
	}
	return filepath.Join(source.Path(catalogRoot(), subscription.Name), CatalogFileName)
}

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
	envelope, err := attest.LoadEnvelope(indexPath(subscription))
	if err != nil {
		return nil, fmt.Errorf("no usable %s: %w", CatalogFileName, err)
	}

	sequenceState, err := catalog.LoadState(statePath(subscription.Name + ".sequence"))
	if err != nil {
		return nil, err
	}
	snapshot, signers, err := catalog.VerifySigners(envelope, trusted, sequenceState, now)
	if err != nil {
		return nil, err
	}
	if err := subscription.Satisfied(signers); err != nil {
		return nil, err
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

// repeatedString collects a flag given more than once, in the order it was given.
type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, ", ") }

func (r *repeatedString) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// mustKeyID reports this machine's key fingerprint, or an empty string if it cannot be read.
func mustKeyID() string {
	public, err := attest.LoadPublicKey(defaultPublicKey())
	if err != nil {
		return ""
	}
	return attest.KeyID(public)
}
