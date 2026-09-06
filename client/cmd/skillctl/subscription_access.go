package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	publicsubscription "github.com/random1st/skilltrust/subscription"
)

// This credential is read for one transaction. Neither a cached source URL nor
// a previous successful request is authorization for another command.
type subscriptionAccess struct {
	organisation string
	catalog      string
	key          ed25519.PrivateKey
	token        string
}

type subscriptionHTTPError struct {
	address string
	status  int
}

func (e subscriptionHTTPError) Error() string {
	return fmt.Sprintf("%s answered HTTP %d; the catalog could not be followed", e.address, e.status)
}

func (e subscriptionHTTPError) unavailable() bool {
	return e.status == http.StatusUnauthorized || e.status == http.StatusForbidden || e.status == http.StatusNotFound
}

type subscriptionAccessRequired struct{ organisation string }

func (e *subscriptionAccessRequired) Error() string { return "this catalog requires team access" }

func subscriptionReadFailure(uri string, err error) error {
	var response subscriptionHTTPError
	return &subscriptionAccessFailure{uri: uri, ownerAction: errors.As(err, &response) && response.unavailable(), cause: err}
}

type subscriptionAccessFailure struct {
	uri         string
	ownerAction bool
	cause       error
}

func (e *subscriptionAccessFailure) Error() string {
	if e.ownerAction {
		return fmt.Sprintf("access to %s is unavailable for this computer; ask that team's owner to restore your membership or machine access, then retry %s subscribe %s. Existing files were kept", e.uri, commandName(), e.uri)
	}
	return fmt.Sprintf("could not confirm current access to %s; check the connection and retry %s subscribe %s. Existing files were kept: %v", e.uri, commandName(), e.uri, e.cause)
}

func (e *subscriptionAccessFailure) Unwrap() error { return e.cause }

func (access *subscriptionAccess) authorize(request *http.Request, now time.Time) error {
	address := request.URL.String()
	descriptor, err := publicsubscription.URL(access.organisation, access.catalog)
	if err != nil {
		return err
	}
	catalog := publicsubscription.Origin + "/v1/catalogs/" + access.organisation + "/" + access.catalog
	allowed := address == descriptor || address == catalog
	if strings.HasPrefix(address, descriptor+"/source/") {
		digest := strings.TrimPrefix(address, descriptor+"/source/")
		expected, err := publicsubscription.SourceURL(access.organisation, access.catalog, digest)
		allowed = err == nil && address == expected
	}
	if request.Method != http.MethodGet || !allowed {
		return fmt.Errorf("refusing to send a team credential outside the requested Axela catalog")
	}
	proof, err := publicsubscription.SignRead(request.Method, address, access.key, now)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+access.token)
	request.Header.Set(publicsubscription.ReadProofHeader, proof)
	return nil
}

func readSubscriptionResolverState(ctx context.Context, org, name string, authenticated, locked bool) (publicSubscriptionState, []Subscription, map[string]ed25519.PublicKey, *subscriptionAccess, error) {
	if !locked {
		unlock, err := acquireConsumerState(ctx)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		defer unlock()
	}
	baseline, subscriptions, pins, err := readPublicSubscriptionStateLocked(name)
	if err != nil || !authenticated {
		return baseline, subscriptions, pins, nil, err
	}
	access, err := loadSubscriptionAccess(org, name)
	return baseline, subscriptions, pins, access, err
}

func loadSubscriptionAccess(org, name string) (*subscriptionAccess, error) {
	if _, err := publicsubscription.URL(org, name); err != nil {
		return nil, err
	}
	for _, path := range []string{connectStatePath(), connectCredentialsPath(), defaultSigningKey(), defaultPublicKey()} {
		if err := regularSubscriptionIdentityFile(path); err != nil {
			return nil, fmt.Errorf("this computer's saved team identity is incomplete or unsafe; keep its existing key and retry %s subscribe axela://%s/%s after repairing it: %w", commandName(), org, name, err)
		}
	}
	current, err := loadSavedConnect()
	if err != nil {
		return nil, err
	}
	if current == nil || current.Audience != publicsubscription.Origin || current.Organisation != org {
		return nil, fmt.Errorf("this computer is connected to another service or team; use that team's URI, or use a separate SKILLTRUST_HOME for axela://%s/%s. The existing connection was kept", org, name)
	}
	pending, _, err := resumeSavedConnect(publicsubscription.Origin, current)
	if err != nil {
		return nil, err
	}
	key, err := validateSubscriptionSigner(false)
	if err != nil {
		return nil, err
	}
	return &subscriptionAccess{organisation: org, catalog: name, key: key, token: pending.Token}, nil
}

func regularSubscriptionIdentityFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular identity file", path)
	}
	return validatePublicDestination(path, false)
}

// Existing partial, symlinked or malformed identities must never be replaced by
// the convenience enrollment path. Only a completely absent signer is new.
func validateSubscriptionSigner(allowMissing bool) (ed25519.PrivateKey, error) {
	_, privateErr := os.Lstat(defaultSigningKey())
	_, publicErr := os.Lstat(defaultPublicKey())
	if allowMissing && os.IsNotExist(privateErr) && os.IsNotExist(publicErr) {
		return nil, nil
	}
	for _, path := range []string{defaultSigningKey(), defaultPublicKey()} {
		if err := regularSubscriptionIdentityFile(path); err != nil {
			return nil, err
		}
	}
	key, err := attest.LoadPrivateKey(defaultSigningKey())
	if err != nil {
		return nil, err
	}
	public, err := attest.LoadPublicKey(defaultPublicKey())
	if err != nil || !bytes.Equal(public, key.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("the existing machine key pair does not match; keep and repair it before connecting")
	}
	return key, nil
}
