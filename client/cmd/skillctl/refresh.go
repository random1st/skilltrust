package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/source"
)

// runRefresh updates the pinned notary keys of catalog subscriptions from each notary's
// signed key-set announcement. This is the consumer half of key rotation: the notary
// announces its next key under a signature from the current one, and this command extends
// the pin along that chain — into the same party, so the rotation pair still counts as
// one signer toward the threshold.
//
// It only ever adds. Removing the outgoing key is a trust decision the operator makes
// with `skillctl trust --remove` once the overlap window closes; an announcement that
// could shrink the pinned set would let whoever signs it unpin keys, and shrinking trust
// on a server's say-so is the opposite of pinning.
func runRefresh(args []string) int {
	flags := flag.NewFlagSet("refresh", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl refresh [catalog]\n\n"+
			"Fetches each notary's signed announcement of its current keys and pins any\n"+
			"newly announced key alongside the one that vouched for it. With a name, only\n"+
			"that catalog is refreshed. Catalogs without a notary URL are skipped.\n\n"+
			"Exit codes: %d done, %d error.\n\nFlags:\n", exitClean, exitUsage)
		flags.PrintDefaults()
	}
	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 1 {
		flags.Usage()
		return exitUsage
	}
	only := flags.Arg(0)

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return fail(err)
	}
	changed := false
	found := false
	for i := range subscriptions {
		if only != "" && subscriptions[i].Name != only {
			continue
		}
		found = true
		if subscriptions[i].CatalogURL == "" {
			if only != "" {
				fmt.Printf("%s has no notary URL; its keys only change by hand\n", only)
			}
			continue
		}
		added, err := refreshSubscription(&subscriptions[i], defaultTrustedKeys())
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: %s: %v\n", subscriptions[i].Name, err)
			continue
		}
		if len(added) == 0 {
			fmt.Printf("%-11s %s\n", "unchanged", subscriptions[i].Name)
			continue
		}
		changed = true
		fmt.Printf("%-11s %s now also pinned for %s\n",
			"pinned", strings.Join(fingerprints(added), ", "), subscriptions[i].Name)
	}
	if only != "" && !found {
		fmt.Fprintf(os.Stderr, "skillctl: nothing here follows %q\n", only)
		return exitUsage
	}
	if changed {
		if err := saveSubscriptions(subscriptions); err != nil {
			return fail(err)
		}
	}
	return exitClean
}

// refreshSubscription fetches the signed key set from this subscription's notary, checks
// it against the keys the subscription already pins, and merges newly announced keys into
// the announcing key's party. It reports the added key ids, empty when nothing changed.
func refreshSubscription(subscription *Subscription, keysPath string) ([]string, error) {
	address, err := keySetURL(subscription.CatalogURL)
	if err != nil {
		return nil, err
	}
	body, err := source.FetchJSON(address)
	if err != nil {
		return nil, err
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("the key set at %s is not a DSSE envelope: %v", address, err)
	}

	trusted, err := attest.LoadTrustedKeys(keysPath)
	if err != nil {
		return nil, err
	}
	set, signers, err := attest.VerifyKeySet(&envelope, trusted)
	if err != nil {
		return nil, fmt.Errorf("the key set at %s does not verify: %w", address, err)
	}

	// The chain of trust is anchored in this subscription's own pins, not the machine's
	// whole trust store: a key pinned for some other catalog vouches for nothing here.
	pinned := map[string]struct{}{}
	for _, key := range subscription.Keys() {
		pinned[key] = struct{}{}
	}
	anchor := ""
	for _, signer := range signers {
		if _, ok := pinned[signer]; ok {
			anchor = signer
			break
		}
	}
	if anchor == "" {
		return nil, fmt.Errorf("the key set at %s is signed by %s, none of which this "+
			"machine pinned for %s", address, strings.Join(fingerprints(signers), ", "),
			subscription.Name)
	}

	var added []string
	for _, announced := range set.Keys {
		if _, already := pinned[announced.ID]; already {
			continue
		}
		public, err := attest.ParsePublicKey([]byte(announced.PublicKey))
		if err != nil {
			return nil, err
		}
		label := subscription.Name + "-" + attest.Fingerprint(announced.ID)
		if err := attest.PinKey(keysPath, label, public); err != nil {
			return nil, err
		}
		added = append(added, announced.ID)
	}
	if len(added) == 0 {
		return nil, nil
	}

	// The new keys join the anchor's party, so the rotation pair counts once toward the
	// threshold. An anchor in no party gets one now, seeded with itself.
	party := ""
	for label, members := range subscription.Parties {
		for _, member := range members {
			if member == anchor {
				party = label
				break
			}
		}
		if party != "" {
			break
		}
	}
	if party == "" {
		party = attest.Fingerprint(anchor)
		if subscription.Parties == nil {
			subscription.Parties = map[string][]string{}
		}
		subscription.Parties[party] = []string{anchor}
	}
	subscription.Parties[party] = append(subscription.Parties[party], added...)
	return added, nil
}

// keySetURL derives the notary's key-set endpoint from a catalog URL: same origin,
// fixed path. The notary that serves the catalog is the notary whose keys rotate.
func keySetURL(catalogURL string) (string, error) {
	parsed, err := url.Parse(catalogURL)
	if err != nil {
		return "", fmt.Errorf("catalog URL %q is not a URL: %w", catalogURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("catalog URL %q names no host", catalogURL)
	}
	return parsed.Scheme + "://" + parsed.Host + "/v1/keys", nil
}
