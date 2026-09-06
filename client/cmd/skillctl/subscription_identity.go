package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	publicsubscription "github.com/random1st/skilltrust/subscription"
)

type subscriptionApprovalPending struct{ uri string }

func (e *subscriptionApprovalPending) Error() string {
	return fmt.Sprintf("finish approval in the browser, then run %s subscribe %s", commandName(), e.uri)
}

// Enrollment grants only a compatible machine identity here. Following another
// catalog, configuring reporting and installing hooks belong to explicit connect.
func (r publicSubscriptionResolver) ensureSubscriptionIdentity(ctx context.Context, org, uri string) error {
	pending, baseline, created, err := prepareSubscriptionIdentity(ctx, org, uri, r.now())
	if err != nil || pending == nil {
		return err
	}
	client := *r.client
	client.Timeout = connectTimeout
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	connection, waiting, err := pollConnectStatusWithClient(&client, publicsubscription.Origin, pending)
	if err != nil {
		return subscriptionApprovalFailure(uri, err)
	}
	if waiting {
		address, err := approvalURL(publicsubscription.Origin, pending.Envelope)
		if err != nil {
			return err
		}
		fmt.Printf("Approve this computer for team %s in your browser.\n", org)
		if created && connectOpenBrowser(address) == nil {
			fmt.Println("Approval opened in your browser.")
		} else {
			fmt.Printf("Approval: %s\n", address)
		}
		deadline := connectNow().Add(connectDefaultWait)
		for waiting && connectNow().Before(deadline) {
			if err := ctx.Err(); err != nil {
				return &subscriptionApprovalPending{uri: uri}
			}
			connectSleep(time.Second)
			connection, waiting, err = pollConnectStatusWithClient(&client, publicsubscription.Origin, pending)
			if err != nil {
				return subscriptionApprovalFailure(uri, err)
			}
		}
		if waiting {
			return &subscriptionApprovalPending{uri: uri}
		}
	}
	if err := validateConnection(publicsubscription.Origin, pending, connection); err != nil {
		return err
	}
	if connection.Organisation != org {
		return fmt.Errorf("Axela approved a different team; approval for %s is required. The existing identity and pending request were kept", org)
	}
	unlock, err := acquireConsumerState(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := baseline.unchanged(); err != nil {
		return err
	}
	for _, path := range []string{connectCredentialsPath(), connectStatePath()} {
		if err := validatePublicDestination(path, false); err != nil {
			return err
		}
	}
	if err := writeOwnerOnlyText(connectCredentialsPath(), pending.Token+"\n"); err != nil {
		return err
	}
	saved := savedConnect{Version: connectRecordVersion, Audience: publicsubscription.Origin,
		Organisation: org, Machine: pending.Machine, MachineKeyID: pending.MachineKeyID,
		IngestURL: connection.IngestURL, DashboardURL: connection.DashboardURL,
		PublisherKeys: connection.PublisherKeys, NotaryKeys: connection.NotaryKeys, Catalogs: connection.Catalogs,
		ConnectedAt: r.now().UTC(), IdentityOnly: true}
	if err := saveHomeJSON(connectStatePath(), saved); err != nil {
		if rollbackErr := os.Remove(connectCredentialsPath()); rollbackErr != nil {
			return fmt.Errorf("connection could not be saved; its credential remains at %s: %w", connectCredentialsPath(), err)
		}
		return err
	}
	return nil
}

func subscriptionApprovalFailure(uri string, err error) error {
	var blocked connectBlocked
	if errors.As(err, &blocked) {
		return fmt.Errorf("this team is not approving this computer; ask its owner to enable your membership and machine access, then retry %s subscribe %s. The pending request was kept", commandName(), uri)
	}
	// Enrollment endpoints may return an arbitrary body. Do not reflect one that
	// could echo the bearer; the saved proof can be resumed after a network error.
	return fmt.Errorf("team approval could not be confirmed; check the connection and retry %s subscribe %s. The pending request was kept", commandName(), uri)
}

func prepareSubscriptionIdentity(ctx context.Context, org, uri string, now time.Time) (*pendingConnect, publicSubscriptionState, bool, error) {
	_, name, err := publicsubscription.ParseURI(uri)
	if err != nil {
		return nil, nil, false, err
	}
	unlock, err := acquireConsumerState(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	defer unlock()
	current, err := loadSavedConnect()
	if err != nil {
		return nil, nil, false, err
	}
	if current != nil {
		_, err := loadSubscriptionAccess(org, name)
		return nil, nil, false, err
	}
	if _, err := os.Lstat(connectCredentialsPath()); !os.IsNotExist(err) {
		return nil, nil, false, fmt.Errorf("a saved credential has no compatible connection record; keep the existing identity and repair it before subscribing")
	}
	if _, err := validateSubscriptionSigner(true); err != nil {
		return nil, nil, false, err
	}
	if err := validatePublicDestination(pendingConnectPath(), false); err != nil {
		return nil, nil, false, err
	}
	pending, err := loadPendingConnect(now)
	if err != nil {
		return nil, nil, false, err
	}
	created := false
	if pending != nil {
		request, _, _, err := readPendingRequest(pending.Envelope, now)
		if err != nil {
			return nil, nil, false, err
		}
		if request.Audience != publicsubscription.Origin || request.Organisation != org {
			return nil, nil, false, fmt.Errorf("another browser approval is already pending; finish %s connect for that request, then retry %s subscribe %s with the matching team or a separate SKILLTRUST_HOME. The pending request was kept", commandName(), commandName(), uri)
		}
		// Reuse the existing key/request binding guard before resuming consent.
		pending, _, err = ensurePendingConnect(publicsubscription.Origin, pending.Machine, pending, now)
		if err != nil {
			return nil, nil, false, err
		}
	}
	if pending == nil || pending.Expired {
		machine := connectMachine("")
		if pending != nil {
			machine = pending.Machine
		}
		pending, created, err = createPendingConnectFor(publicsubscription.Origin, machine, org, now)
		if err != nil {
			return nil, nil, false, err
		}
	}
	baseline, _, _, err := readPublicSubscriptionStateLocked(name)
	return pending, baseline, created, err
}
