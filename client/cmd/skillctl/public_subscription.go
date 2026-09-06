package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
	publicsubscription "github.com/random1st/skilltrust/subscription"
)

// The production factory has no origin override. Tests replace the transport and
// source fetcher explicitly; URI input can never select a host or local file.
var newPublicSubscriptionResolver = func() publicSubscriptionResolver {
	return publicSubscriptionResolver{
		client: connectHTTPClient(15 * time.Second), now: time.Now,
		fetch: source.FetchContext, rename: os.Rename,
	}
}

type publicSubscriptionResolver struct {
	client *http.Client
	now    func() time.Time
	fetch  func(context.Context, string, string, string, string) (source.Source, error)
	rename func(string, string) error
}

func runPublicSubscribe(raw string) int {
	resolver := newPublicSubscriptionResolver()
	count, uncovered, err := resolver.subscribe(context.Background(), raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", commandName(), err)
		var pending *subscriptionApprovalPending
		if errors.As(err, &pending) {
			return exitFindings
		}
		return exitUsage
	}
	fmt.Printf("Following %s: %d signed plugin%s.\n", raw, count, plural(count, "", "s"))
	if uncovered > 0 {
		fmt.Printf("%d source entr%s have incomplete or no signature coverage.\n", uncovered, plural(uncovered, "y", "ies"))
	}
	fmt.Printf("Run: %s doctor — check what is installed on this computer.\n", commandName())
	return exitClean
}

func (r publicSubscriptionResolver) get(ctx context.Context, address string, limit int64) ([]byte, error) {
	return r.getWithAccess(ctx, address, limit, nil)
}

func (r publicSubscriptionResolver) getWithAccess(ctx context.Context, address string, limit int64, access *subscriptionAccess) ([]byte, error) {
	// Every permitted URL is produced by the fixed-origin descriptor contract.
	if !strings.HasPrefix(address, publicsubscription.Origin+"/") {
		return nil, fmt.Errorf("the subscription URL is outside Axela")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	if access != nil {
		if err := access.authorize(request, r.now()); err != nil {
			return nil, err
		}
	}
	// Never follow a redirect, including a same-origin redirect: a read proof is
	// bound to the exact address, and a bearer must not escape that address.
	client := *r.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the subscription: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, subscriptionHTTPError{address: address, status: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("the subscription response exceeds %d bytes", limit)
	}
	return body, nil
}

func (r publicSubscriptionResolver) subscribe(ctx context.Context, raw string) (int, int, error) {
	count, uncovered, err := r.resolve(ctx, raw, false, false)
	var required *subscriptionAccessRequired
	if !errors.As(err, &required) {
		return count, uncovered, err
	}
	if err := r.ensureSubscriptionIdentity(ctx, required.organisation, raw); err != nil {
		return 0, 0, err
	}
	return r.resolve(ctx, raw, true, false)
}

func (r publicSubscriptionResolver) resolve(ctx context.Context, raw string, authenticated, locked bool) (int, int, error) {
	org, name, err := publicsubscription.ParseURI(raw)
	if err != nil {
		return 0, 0, err
	}
	baseline, subscriptions, pins, access, err := readSubscriptionResolverState(ctx, org, name, authenticated, locked)
	if err != nil {
		return 0, 0, err
	}
	for _, existing := range subscriptions {
		if existing.Name == name && existing.Access != "" && !authenticated {
			return 0, 0, &subscriptionAccessRequired{organisation: org}
		}
	}
	now := r.now().UTC()
	notaryKeys, currentNotary, keysSeen, err := r.notaryKeys(ctx, name, subscriptions, pins, now)
	if err != nil {
		return 0, 0, err
	}
	address, _ := publicsubscription.URL(org, name)
	body, err := r.getWithAccess(ctx, address, publicsubscription.MaxBytes, access)
	if err != nil {
		var unavailable subscriptionHTTPError
		if !authenticated && errors.As(err, &unavailable) && unavailable.unavailable() {
			return 0, 0, &subscriptionAccessRequired{organisation: org}
		}
		if authenticated {
			return 0, 0, subscriptionReadFailure(raw, err)
		}
		return 0, 0, err
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return 0, 0, fmt.Errorf("the subscription descriptor is not readable")
	}
	descriptor, _, err := publicsubscription.Verify(&envelope, attest.NewTrustedKeys(currentNotary...), org, name, now)
	if err != nil {
		return 0, 0, err
	}
	if descriptor.Access == "team" && access == nil {
		return 0, 0, &subscriptionAccessRequired{organisation: org}
	}
	entry, publisherKeys, err := publicSubscriptionEntry(descriptor, notaryKeys, keysSeen)
	if err != nil {
		return 0, 0, err
	}
	for _, existing := range subscriptions {
		if existing.Name != entry.Name {
			continue
		}
		for _, key := range publisherKeys {
			pinned := false
			for _, trusted := range pins {
				pinned = pinned || bytes.Equal(trusted, key)
			}
			if !pinned {
				return 0, 0, fmt.Errorf("%s names a publisher key no longer pinned on this computer; review the trust change explicitly", entry.Name)
			}
		}
	}
	if err := mergePublicSubscription(&subscriptions, &entry); err != nil {
		return 0, 0, err
	}
	var catalogAccess *subscriptionAccess
	if descriptor.Access == "team" {
		catalogAccess = access
	}
	catalogBytes, err := r.getWithAccess(ctx, descriptor.CatalogURL, source.MaxIndexBytes, catalogAccess)
	if err != nil {
		if catalogAccess != nil {
			return 0, 0, subscriptionReadFailure(raw, err)
		}
		return 0, 0, err
	}
	sum := sha256.Sum256(catalogBytes)
	if hex.EncodeToString(sum[:]) != descriptor.CatalogDigest {
		return 0, 0, fmt.Errorf("the served catalog does not match its signed subscription descriptor; fetch it again")
	}
	var catalogEnvelope attest.Envelope
	if err := json.Unmarshal(catalogBytes, &catalogEnvelope); err != nil {
		return 0, 0, fmt.Errorf("the signed catalog is not readable")
	}
	state, err := catalog.LoadState(snapshotStatePath(entry))
	if err != nil {
		return 0, 0, err
	}
	trustedKeys := append(append([]ed25519.PublicKey{}, publisherKeys...), currentNotary...)
	for _, key := range pins {
		if containsPublicKeyID(entry.Keys(), attest.KeyID(key)) && !containsPublicKeyID(entry.Parties[notaryParty], attest.KeyID(key)) {
			trustedKeys = append(trustedKeys, key)
		}
	}
	trusted := attest.NewTrustedKeys(trustedKeys...)
	snapshot, signers, err := catalog.VerifySigners(&catalogEnvelope, trusted, state, now)
	if err != nil {
		return 0, 0, err
	}
	if snapshot.Name != descriptor.Catalog || snapshot.Sequence < 1 || snapshot.IssuedAt.IsZero() || snapshot.ValidUntil.Before(snapshot.IssuedAt) {
		return 0, 0, fmt.Errorf("the signed catalog has an invalid name, sequence or lifetime")
	}
	if descriptor.ExpiresAt.After(snapshot.ValidUntil) {
		return 0, 0, fmt.Errorf("the subscription descriptor outlives its catalog")
	}
	if err := entry.Satisfied(signers); err != nil {
		return 0, 0, err
	}
	for _, key := range publisherKeys {
		if !containsPublicKeyID(signers, attest.KeyID(key)) {
			return 0, 0, fmt.Errorf("the descriptor names a publisher key that did not sign this catalog")
		}
	}

	// Only verified data reaches the owned staging tree. The local check signer
	// is prepared later, alongside the final state; no enrollment, reporting
	// destination or client setting is created here.
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return 0, 0, err
	}
	stage, err := os.MkdirTemp(Home(), ".public-subscribe-*")
	if err != nil {
		return 0, 0, err
	}
	keepStage := false
	defer func() {
		if !keepStage {
			os.RemoveAll(stage)
		}
	}()
	if descriptor.Access == "team" {
		payload, err := r.getWithAccess(ctx, descriptor.SourceURL, publicsubscription.MaxSourceBytes, access)
		if err != nil {
			return 0, 0, subscriptionReadFailure(raw, err)
		}
		if err := publicsubscription.ExtractSource(payload, source.Path(stage, name), descriptor.SourceDigest); err != nil {
			return 0, 0, err
		}
	} else {
		cloneRef := strings.TrimPrefix(strings.TrimPrefix(descriptor.Ref, "refs/heads/"), "refs/tags/")
		fetched, err := r.fetch(ctx, stage, name, descriptor.Repository, cloneRef)
		if err != nil {
			return 0, 0, err
		}
		if fetched.Commit != descriptor.Commit {
			return 0, 0, fmt.Errorf("the repository ref moved since this catalog was published; ask its publisher to publish the current commit")
		}
	}
	count, uncovered, err := verifyPublicSubscriptionSource(source.Path(stage, name), snapshot)
	if err != nil {
		return 0, 0, err
	}
	for _, pair := range []struct {
		party string
		keys  []ed25519.PublicKey
	}{{"catalog", publisherKeys}, {"notary", notaryKeys}} {
		for _, key := range pair.keys {
			label := pair.party + ":" + name + ":" + attest.KeyID(key)
			if previous, exists := pins[label]; exists && !bytes.Equal(previous, key) {
				return 0, 0, fmt.Errorf("%s already pins another key; review the trust change explicitly", label)
			}
			pins[label] = key
		}
	}
	if locked {
		err = r.saveLocked(baseline, stage, entry, subscriptions, pins, catalogBytes, snapshot.Sequence, now)
	} else {
		err = r.save(ctx, baseline, stage, entry, subscriptions, pins, catalogBytes, snapshot.Sequence, now)
	}
	if err != nil {
		var recovery *publicSubscriptionRecoveryError
		keepStage = errors.As(err, &recovery)
		return 0, 0, err
	}
	return count, uncovered, nil
}

func (r publicSubscriptionResolver) notaryKeys(ctx context.Context, target string, subscriptions []Subscription, pins map[string]ed25519.PublicKey, now time.Time) ([]ed25519.PublicKey, []ed25519.PublicKey, time.Time, error) {
	known := map[string]ed25519.PublicKey{}
	var seen time.Time
	// An existing catalog keeps its own authority. Another catalog's notary
	// cannot sign away this catalog's pins without a valid rotation chain.
	for _, entry := range subscriptions {
		if entry.Name == target {
			subscriptions = []Subscription{entry}
			break
		}
	}
	for _, entry := range subscriptions {
		if !strings.HasPrefix(entry.CatalogURL, publicsubscription.Origin+"/") {
			continue
		}
		if len(entry.Parties[notaryParty]) == 0 {
			return nil, nil, seen, fmt.Errorf("%s already follows Axela without an explicit notary party; review its pinned keys before adding a public subscription", entry.Name)
		}
		anchored := false
		for _, id := range entry.Parties[notaryParty] {
			for _, key := range pins {
				if attest.KeyID(key) == id {
					known[id] = key
					anchored = true
				}
			}
		}
		if !anchored {
			return nil, nil, seen, fmt.Errorf("%s has no pinned notary key; restore an established pin before subscribing", entry.Name)
		}
		if entry.KeysSeen.After(seen) {
			seen = entry.KeysSeen
		}
	}
	if len(known) == 0 {
		body, err := r.get(ctx, publicsubscription.Origin+"/notary.pub", publicsubscription.MaxBytes)
		if err != nil {
			return nil, nil, seen, err
		}
		key, err := attest.ParsePublicKey(body)
		if err != nil {
			return nil, nil, seen, fmt.Errorf("Axela returned an unusable notary key")
		}
		known[attest.KeyID(key)] = key
	}
	body, err := r.get(ctx, publicsubscription.Origin+"/v1/keys", publicsubscription.MaxBytes)
	if err != nil {
		return nil, nil, seen, err
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, seen, fmt.Errorf("Axela returned an unreadable notary key set")
	}
	set, _, err := attest.VerifyKeySet(&envelope, attest.NewTrustedKeys(sortedPublicKeys(known)...), now)
	if err != nil {
		return nil, nil, seen, err
	}
	if set.IssuedAt.After(now.Add(5*time.Minute)) || set.IssuedAt.Before(seen) {
		return nil, nil, seen, fmt.Errorf("the notary key announcement is from the future or older than the one already pinned")
	}
	var current []ed25519.PublicKey
	for _, announced := range set.Keys {
		key, _ := attest.ParsePublicKey([]byte(announced.PublicKey)) // VerifyKeySet checked every key and signature.
		if known[announced.ID] == nil && !set.IssuedAt.After(seen) {
			return nil, nil, seen, fmt.Errorf("a replayed notary announcement cannot add a new key")
		}
		known[announced.ID] = key
		current = append(current, key)
	}
	return sortedPublicKeys(known), current, set.IssuedAt, nil
}

func sortedPublicKeys(keys map[string]ed25519.PublicKey) []ed25519.PublicKey {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]ed25519.PublicKey, 0, len(ids))
	for _, id := range ids {
		result = append(result, keys[id])
	}
	return result
}

func publicSubscriptionEntry(d *publicsubscription.Descriptor, notary []ed25519.PublicKey, seen time.Time) (Subscription, []ed25519.PublicKey, error) {
	entry := Subscription{Name: d.Catalog, Repository: d.Repository, Ref: d.Ref, CatalogURL: d.CatalogURL, CatalogName: d.Catalog,
		AxelaURI: "axela://" + d.Organisation + "/" + d.Catalog, Access: d.Access,
		Threshold: 2, Parties: map[string][]string{"publisher": {}, notaryParty: {}}, KeysSeen: seen}
	for _, key := range notary {
		entry.Parties[notaryParty] = append(entry.Parties[notaryParty], attest.KeyID(key))
	}
	var publisher []ed25519.PublicKey
	for _, pem := range d.PublisherKeys {
		key, err := attest.ParsePublicKey([]byte(pem))
		if err != nil {
			return entry, nil, err
		}
		id := attest.KeyID(key)
		if containsPublicKeyID(entry.Parties[notaryParty], id) {
			return entry, nil, fmt.Errorf("the publisher and notary must use different keys")
		}
		entry.Parties["publisher"] = append(entry.Parties["publisher"], id)
		publisher = append(publisher, key)
	}
	for _, party := range sortedParties(entry.Parties) {
		sort.Strings(entry.Parties[party])
		entry.KeyIDs = append(entry.KeyIDs, entry.Parties[party]...)
	}
	return entry, publisher, nil
}

func mergePublicSubscription(subscriptions *[]Subscription, entry *Subscription) error {
	for index, existing := range *subscriptions {
		if existing.Name != entry.Name {
			continue
		}
		if existing.Repository != entry.Repository || existing.Ref != entry.Ref || existing.CatalogURL != entry.CatalogURL || existing.CatalogName != "" && existing.CatalogName != entry.CatalogName {
			return fmt.Errorf("%s already follows a different source; review the subscription change explicitly", entry.Name)
		}
		if existing.AxelaURI != "" && existing.AxelaURI != entry.AxelaURI || existing.Access != "" && existing.Access != entry.Access {
			return fmt.Errorf("%s already follows another Axela URI or access mode; review the subscription change explicitly", entry.Name)
		}
		oldPublisher := existing.Parties["publisher"]
		if len(oldPublisher) == 0 {
			return fmt.Errorf("%s already pins different publisher keys; review the trust change explicitly", entry.Name)
		}
		for _, id := range entry.Parties["publisher"] {
			if !containsPublicKeyID(oldPublisher, id) {
				return fmt.Errorf("%s already pins different publisher keys; review the trust change explicitly", entry.Name)
			}
		}
		for _, id := range entry.Parties[notaryParty] {
			if containsPublicKeyID(existing.Keys(), id) && !containsPublicKeyID(existing.Parties[notaryParty], id) {
				return fmt.Errorf("%s already trusts a proposed notary as another signer; the parties must stay independent", entry.Name)
			}
		}
		// A descriptor lists actual signers of this version, not a replacement
		// trust policy. Preserve additional publisher keys and stronger thresholds.
		for party, ids := range existing.Parties {
			if party != notaryParty {
				entry.Parties[party] = append([]string(nil), ids...)
			}
		}
		for _, id := range existing.Keys() {
			if !containsPublicKeyID(existing.Parties[notaryParty], id) && !containsPublicKeyID(entry.KeyIDs, id) {
				entry.KeyIDs = append(entry.KeyIDs, id)
			}
		}
		if existing.Required() > entry.Required() {
			entry.Threshold = existing.Required()
		}
		if err := assertBootstrapPartiesCompatible(existing, *entry); err != nil {
			return err
		}
		for _, id := range existing.Keys() {
			if !containsPublicKeyID(entry.Keys(), id) {
				// A retired notary key removed explicitly from the trust store is
				// no longer authority. The surviving pin verified the current key
				// set; do not restore the retired key from an old subscription ID.
				if containsPublicKeyID(existing.Parties[notaryParty], id) {
					continue
				}
				return fmt.Errorf("%s already pins another signer; subscribing will not remove it", entry.Name)
			}
		}
		(*subscriptions)[index] = *entry
		return nil
	}
	if _, err := os.Lstat(source.Path(catalogRoot(), entry.Name)); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return fmt.Errorf("%s already has an unregistered source cache; move it aside before subscribing", entry.Name)
	}
	*subscriptions = append(*subscriptions, *entry)
	return nil
}

func containsPublicKeyID(ids []string, wanted string) bool {
	for _, id := range ids {
		if id == wanted {
			return true
		}
	}
	return false
}

func verifyPublicSubscriptionSource(repository string, snapshot *catalog.Snapshot) (int, int, error) {
	manifest, err := marketplace.Load(repository)
	if err != nil {
		return 0, 0, fmt.Errorf("the published source is not a usable plugin marketplace: %w", err)
	}
	if manifest.Name != snapshot.Name {
		return 0, 0, fmt.Errorf("the repository marketplace and signed catalog have different names")
	}
	coverage, err := marketplace.Plan(repository, manifest)
	if err != nil {
		return 0, 0, err
	}
	actual := map[string]catalog.Managed{}
	for _, skill := range coverage.Signed {
		if _, duplicate := actual[skill.Name]; duplicate {
			return 0, 0, fmt.Errorf("the repository repeats a plugin name")
		}
		actual[skill.Name] = skill
	}
	for _, skill := range snapshot.Skills {
		found, exists := actual[skill.Name]
		if !exists || found.Digest != skill.Digest || found.Version != skill.Version || skill.Path != "" {
			return 0, 0, fmt.Errorf("the published plugin %q does not match the repository at its signed commit", skill.Name)
		}
		delete(actual, skill.Name)
	}
	if len(actual) != 0 || len(snapshot.Skills) == 0 {
		return 0, 0, fmt.Errorf("the repository and catalog do not cover the same nonempty set of plugins")
	}
	uncovered := len(coverage.Unversioned) + len(coverage.Partial)
	for _, names := range coverage.Remote {
		uncovered += len(names)
	}
	return len(snapshot.Skills), uncovered, nil
}
