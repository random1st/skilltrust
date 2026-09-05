package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	// KeysSeen is the issue time of the newest key-set announcement this subscription has
	// acted on. An announcement no newer than this is refused: announcements stay valid
	// under whichever key survives a rotation, so without a monotonic floor an attacker —
	// or a stale cache — could replay an old overlap document and re-pin a key the
	// operator deliberately retired, undoing the one recovery the design offers.
	KeysSeen time.Time `json:"keys_seen,omitempty"`
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

// notaryParty is the label a notary's keys are grouped under at subscribe time. One label
// rather than one per notary: a subscription follows exactly one catalog URL, so its
// countersigner is one signer whatever number of keys a rotation has it holding.
const notaryParty = "notary"

// catalogNameOK is the notary's own name allowlist, applied on this side too. The name
// becomes a directory and a git checkout path here, so accepting a traversal would let a
// catalog name reach outside the managed tree.
var catalogNameOK = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// signerCount is how many distinct signers this subscription pins: each party once, plus
// every ungrouped key. It is the ceiling a threshold can ask for.
func (s Subscription) signerCount() int {
	distinct := map[string]struct{}{}
	for _, party := range s.partyOf() {
		distinct[party] = struct{}{}
	}
	return len(distinct)
}

// mergeParties keeps groupings a previous subscription had learned, drops any key the new
// subscription no longer pins, and lets the new grouping win where both name a key.
//
// Re-subscribing is how people change a URL or add a key, and before this it silently
// discarded the parties `refresh` had built during a rotation — turning one mid-rotation
// notary back into two signers, which is precisely the count a threshold of two exists to
// require of two different people.
func mergeParties(previous, current map[string][]string, pinned []string) map[string][]string {
	if len(previous) == 0 && len(current) == 0 {
		return nil
	}
	stillPinned := map[string]struct{}{}
	for _, key := range pinned {
		stillPinned[key] = struct{}{}
	}
	claimed := map[string]struct{}{}
	merged := map[string][]string{}
	add := func(source map[string][]string) {
		for _, party := range sortedParties(source) {
			for _, key := range source[party] {
				if _, keep := stillPinned[key]; !keep {
					continue
				}
				if _, taken := claimed[key]; taken {
					continue
				}
				claimed[key] = struct{}{}
				merged[party] = append(merged[party], key)
			}
		}
	}
	add(current)
	add(previous)
	if len(merged) == 0 {
		return nil
	}
	return merged
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
	var notaryKeyPaths repeatedString
	flags.Var(&notaryKeyPaths, "notary-key",
		"PEM public key of the notary countersigning this catalog (repeatable; several keys "+
			"mid-rotation are one signer and count once toward the threshold)")
	threshold := flags.Int("threshold", 0,
		"how many distinct signers must have signed; the default is every signer pinned here, "+
			"which is what makes a single stolen key insufficient")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 || len(keyPaths)+len(notaryKeyPaths) == 0 {
		flags.Usage()
		return exitUsage
	}

	repository := flags.Arg(0)
	catalogName := *name
	if catalogName == "" {
		catalogName = source.NameFor(repository)
	}
	// The name becomes a directory under the catalog root and a checkout git writes into,
	// so it is checked against the same allowlist the notary applies to the names it
	// stores. A tool that runs under an agent's instruction must not accept "../.." as a
	// short name for anything.
	if !catalogNameOK.MatchString(catalogName) {
		fmt.Fprintf(os.Stderr, "skillctl: %q is not usable as a catalog name; letters, "+
			"digits, dashes and underscores only\n", catalogName)
		return exitUsage
	}

	pin := func(path, label string) (string, error) {
		public, err := attest.LoadPublicKey(path)
		if err != nil {
			return "", err
		}
		if err := attest.PinKey(defaultTrustedKeys(), label, public); err != nil {
			return "", err
		}
		return attest.KeyID(public), nil
	}

	var keyIDs []string
	for index, path := range keyPaths {
		label := "catalog:" + catalogName
		if len(keyPaths) > 1 {
			label = fmt.Sprintf("%s:%d", label, index+1)
		}
		id, err := pin(path, label)
		if err != nil {
			return fail(err)
		}
		keyIDs = append(keyIDs, id)
	}

	// Notary keys are pinned into one party. Several of them exist only mid-rotation and
	// belong to one signer; counted separately they would satisfy a threshold of two on
	// their own, which is exactly the "a compromised notary publishes nothing alone"
	// property the threshold is sold on.
	var parties map[string][]string
	for index, path := range notaryKeyPaths {
		label := fmt.Sprintf("notary:%s", catalogName)
		if len(notaryKeyPaths) > 1 {
			label = fmt.Sprintf("%s:%d", label, index+1)
		}
		id, err := pin(path, label)
		if err != nil {
			return fail(err)
		}
		if parties == nil {
			parties = map[string][]string{}
		}
		parties[notaryParty] = append(parties[notaryParty], id)
		keyIDs = append(keyIDs, id)
	}

	signers := len(keyPaths)
	if len(notaryKeyPaths) > 0 {
		signers++
	}
	if *threshold == 0 {
		// Every signer pinned here must sign. Defaulting to one would make the second
		// signature — the whole reason a notary exists — optional on the machine that
		// decides, and a consumer who pinned two signers plainly meant to require both.
		*threshold = signers
	}
	if *threshold > signers {
		fmt.Fprintf(os.Stderr, "skillctl: --threshold %d needs at least that many distinct "+
			"signers pinned (%d here); a requirement no set of keys can meet would refuse "+
			"every index\n", *threshold, signers)
		return exitUsage
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
		KeyIDs: keyIDs, Threshold: *threshold, Parties: parties,
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
			// Carrying these forward is what stops a re-subscribe from being a silent
			// trust reset. Parties grouped by an earlier rotation would otherwise split
			// back into one-key signers — handing a mid-rotation notary two votes — and a
			// reset KeysSeen would re-open the replay window on key-set announcements.
			entry.Parties = mergeParties(existing.Parties, entry.Parties, entry.Keys())
			entry.KeysSeen = existing.KeysSeen
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
	if len(entry.Parties) > 0 {
		for _, party := range sortedParties(entry.Parties) {
			fmt.Printf("%-11s %s counts as one signer\n", party,
				strings.Join(fingerprints(entry.Parties[party]), " + "))
		}
	}
	fmt.Printf("threshold   %d of %d signers must sign\n\n", entry.Threshold, entry.signerCount())
	fmt.Printf("Next: skillctl sync -report-only   — see what this catalog would change\n")
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

func snapshotStatePath(subscription Subscription) string {
	return statePath(subscription.Name + ".sequence")
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
	return fetchCatalogContext(context.Background(), subscription)
}

func fetchCatalogContext(ctx context.Context, subscription Subscription) (source.Source, error) {
	return source.FetchContext(ctx, catalogRoot(), subscription.Name,
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
	return readSnapshotPath(indexPath(subscription), subscription, trusted, now, persist)
}

func readSnapshotPath(
	path string,
	subscription Subscription,
	trusted *attest.TrustedKeys,
	now time.Time,
	persist bool,
) (*catalog.Snapshot, error) {
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		return nil, fmt.Errorf("no usable %s: %w", CatalogFileName, err)
	}

	sequenceState, err := catalog.LoadState(snapshotStatePath(subscription))
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
		if err := sequenceState.Save(snapshotStatePath(subscription), snapshot.Sequence, now); err != nil {
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

func saveSnapshotSequence(subscription Subscription, sequence int64, now time.Time) error {
	state, err := catalog.LoadState(snapshotStatePath(subscription))
	if err != nil {
		return err
	}
	return state.Save(snapshotStatePath(subscription), sequence, now)
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
