package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	publicsubscription "github.com/random1st/skilltrust/subscription"
)

func teamSubscriptionURI(entry Subscription) (string, error) {
	org, name, err := publicsubscription.ParseURI(entry.AxelaURI)
	if err != nil || entry.Access != "team" || name != entry.Name || name != entry.CatalogName || entry.CatalogURL != publicsubscription.Origin+"/v1/catalogs/"+org+"/"+name {
		return "", fmt.Errorf("%s has no valid team subscription binding; retry %s subscribe with the team's axela:// address", entry.Name, commandName())
	}
	return entry.AxelaURI, nil
}

// Old browser bootstrap records have no public/private contract. Require an
// explicit URI upgrade instead of interpreting network failure as public access.
func legacyAxelaSubscription(entry Subscription) bool {
	return entry.AxelaURI == "" && strings.HasPrefix(entry.CatalogURL, publicsubscription.Origin+"/v1/catalogs/")
}

func legacyAxelaUpgrade(entry Subscription) error {
	parts := strings.Split(strings.TrimPrefix(entry.CatalogURL, publicsubscription.Origin+"/v1/catalogs/"), "/")
	if len(parts) == 2 {
		uri := "axela://" + parts[0] + "/" + parts[1]
		if _, _, err := publicsubscription.ParseURI(uri); err == nil {
			return fmt.Errorf("%s needs its current access and source binding checked; run %s subscribe %s. Existing files were kept", entry.Name, commandName(), uri)
		}
	}
	return fmt.Errorf("%s needs a valid Axela subscription address; ask its owner for the axela:// address", entry.Name)
}

// The command already holds the consumer state lock. Reuse the complete signed
// descriptor/catalog/source transaction, with no browser or cached-access path.
func refreshTeamSubscription(ctx context.Context, entry Subscription, now time.Time) (*catalog.Snapshot, Subscription, error) {
	uri, err := teamSubscriptionURI(entry)
	if err != nil {
		return nil, entry, err
	}
	resolver := newPublicSubscriptionResolver()
	if _, _, err := resolver.resolve(ctx, uri, true, true); err != nil {
		return nil, entry, err
	}
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return nil, entry, err
	}
	for _, current := range subscriptions {
		if current.Name == entry.Name {
			trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
			if err != nil {
				return nil, entry, err
			}
			snapshot, err := readSnapshotOnly(current, trusted, now)
			return snapshot, current, err
		}
	}
	return nil, entry, fmt.Errorf("%s is no longer followed; no private files will be installed", entry.Name)
}
