package main

import (
	"crypto/ed25519"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/enrollment"
)

func TestResolveConnectBaseDefaultsToAxela(t *testing.T) {
	base, err := resolveConnectBase("", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if base != connectDefaultBaseURL {
		t.Fatalf("base = %q, want %q", base, connectDefaultBaseURL)
	}
}

func TestReceiptAcceptedRequiresTheExactCurrentCheckReceipt(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	oldNow := connectNow
	connectNow = func() time.Time { return now }
	defer func() { connectNow = oldNow }()

	const (
		expectedURL    = "https://axela.app/v1/events"
		expectedSigner = "sha256:machine"
		expectedDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)

	writeReceipt := func(t *testing.T, status connectStatusFile) {
		t.Helper()
		status.Version = connectStatusVersion
		if err := saveHomeJSON(connectStatusPath(), status); err != nil {
			t.Fatal(err)
		}
	}

	writeReceipt(t, connectStatusFile{
		AcceptedURL: expectedURL,
		AcceptedAt:  now.Add(-time.Minute).Format(time.RFC3339),
		Signer:      expectedSigner,
		Digest:      expectedDigest,
	})
	if !receiptAccepted(expectedDigest, expectedSigner, expectedURL) {
		t.Fatal("exact matching receipt should count")
	}

	cases := []struct {
		name   string
		status connectStatusFile
	}{
		{
			name: "wrong digest",
			status: connectStatusFile{
				AcceptedURL: expectedURL,
				AcceptedAt:  now.Add(-time.Minute).Format(time.RFC3339),
				Signer:      expectedSigner,
				Digest:      strings.Repeat("ab", 32),
			},
		},
		{
			name: "wrong signer",
			status: connectStatusFile{
				AcceptedURL: expectedURL,
				AcceptedAt:  now.Add(-time.Minute).Format(time.RFC3339),
				Signer:      "sha256:other-machine",
				Digest:      expectedDigest,
			},
		},
		{
			name: "wrong url",
			status: connectStatusFile{
				AcceptedURL: "https://axela.app/v1/events/other",
				AcceptedAt:  now.Add(-time.Minute).Format(time.RFC3339),
				Signer:      expectedSigner,
				Digest:      expectedDigest,
			},
		},
		{
			name: "stale old receipt",
			status: connectStatusFile{
				AcceptedURL: expectedURL,
				AcceptedAt:  now.Add(-6 * time.Minute).Format(time.RFC3339),
				Signer:      expectedSigner,
				Digest:      expectedDigest,
			},
		},
		{
			name: "stale future receipt",
			status: connectStatusFile{
				AcceptedURL: expectedURL,
				AcceptedAt:  now.Add(6 * time.Minute).Format(time.RFC3339),
				Signer:      expectedSigner,
				Digest:      expectedDigest,
			},
		},
		{
			name: "invalid time",
			status: connectStatusFile{
				AcceptedURL: expectedURL,
				AcceptedAt:  "not-a-time",
				Signer:      expectedSigner,
				Digest:      expectedDigest,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeReceipt(t, tc.status)
			if receiptAccepted(expectedDigest, expectedSigner, expectedURL) {
				t.Fatalf("receipt with %s was accepted", tc.name)
			}
		})
	}
}

func TestLoadPendingConnectKeepsExpiredRequestForResume(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	token := strings.Repeat("ab", 32)
	request := enrollment.Request{
		Audience:    connectDefaultBaseURL,
		Nonce:       strings.Repeat("cd", 32),
		Machine:     "Work laptop",
		TokenDigest: secretDigest(token),
		IssuedAt:    now.Add(-enrollment.Lifetime),
		ExpiresAt:   now.Add(-time.Minute),
	}
	envelope, err := enrollment.Sign(request, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveHomeJSON(pendingConnectPath(), pendingConnect{
		Version:     connectPendingVersion,
		Audience:    connectDefaultBaseURL,
		Machine:     request.Machine,
		Token:       token,
		Envelope:    envelope,
		RequestedAt: request.IssuedAt,
	}); err != nil {
		t.Fatal(err)
	}

	pending, err := loadPendingConnect(now)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil {
		t.Fatal("pending request was discarded")
	}
	if !pending.Expired {
		t.Fatal("expired request should be kept and marked expired for resume")
	}
	if pending.MachineKeyID != attest.KeyID(public) {
		t.Fatalf("machine key id = %q, want %q", pending.MachineKeyID, attest.KeyID(public))
	}
}

func TestSaveBootstrapSubscriptionsUsesPublisherAndNotaryParties(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	publisherOneID, publisherOne := encodedConnectKey(t)
	publisherTwoID, publisherTwo := encodedConnectKey(t)
	notaryID, notary := encodedConnectKey(t)

	attention, err := saveBootstrapSubscriptions(connectDefaultBaseURL, &enrollment.Connection{
		PublisherKeys: []string{publisherOne, publisherTwo},
		NotaryKeys:    []string{notary},
		Catalogs: []enrollment.Catalog{{
			Name:       "acme",
			Repository: "https://github.com/acme/skills",
			Ref:        "main",
			URL:        "https://axela.app/v1/catalogs/acme/acme",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attention) != 0 {
		t.Fatalf("attention = %v, want none", attention)
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(subscriptions) != 1 {
		t.Fatalf("subscriptions = %d, want 1", len(subscriptions))
	}
	subscription := subscriptions[0]
	if subscription.Required() != 2 {
		t.Fatalf("required = %d, want 2", subscription.Required())
	}
	if got := subscription.Parties["publisher"]; len(got) != 2 {
		t.Fatalf("publisher party = %v, want 2 keys", got)
	}
	if got := subscription.Parties[notaryParty]; len(got) != 1 || got[0] != notaryID {
		t.Fatalf("notary party = %v, want [%s]", got, notaryID)
	}
	if err := subscription.Satisfied([]string{publisherOneID, notaryID}); err != nil {
		t.Fatalf("publisher + notary should satisfy threshold: %v", err)
	}
	if err := subscription.Satisfied([]string{publisherOneID, publisherTwoID}); err == nil {
		t.Fatal("two publisher signatures without the notary must not satisfy the hosted threshold")
	}
}

func TestSaveBootstrapSubscriptionsDoesNotWeakenExistingThreshold(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	publisherID, publisher := encodedConnectKey(t)
	notaryID, _ := encodedConnectKey(t)
	if err := saveBootstrapSubscriptionsFile([]Subscription{{
		Name:       "acme",
		Repository: "https://github.com/acme/skills",
		CatalogURL: "https://axela.app/v1/catalogs/acme/acme",
		KeyIDs:     []string{publisherID, notaryID},
		Threshold:  2,
		Parties: map[string][]string{
			"publisher": {publisherID},
			notaryParty: {notaryID},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	_, err := saveBootstrapSubscriptions(connectDefaultBaseURL, &enrollment.Connection{
		PublisherKeys: []string{publisher},
		Catalogs: []enrollment.Catalog{{
			Name:       "acme",
			Repository: "https://github.com/acme/skills",
		}},
	})
	if err == nil {
		t.Fatal("existing stricter subscription must not be weakened silently")
	}
}

func TestSaveBootstrapSubscriptionsRejectsConflictingBootstrapChanges(t *testing.T) {
	cases := []struct {
		name       string
		catalog    enrollment.Catalog
		publishers func(t *testing.T, existing string) []string
		notaries   func(t *testing.T, existing string) []string
		want       string
	}{
		{
			name: "repository mismatch",
			catalog: enrollment.Catalog{
				Name:       "acme",
				Repository: "https://github.com/acme/other-skills",
				Ref:        "main",
				URL:        "https://axela.app/v1/catalogs/acme/acme",
			},
			publishers: func(_ *testing.T, existing string) []string { return []string{existing} },
			notaries:   func(_ *testing.T, existing string) []string { return []string{existing} },
			want:       "different repository, ref or catalog URL",
		},
		{
			name: "ref mismatch",
			catalog: enrollment.Catalog{
				Name:       "acme",
				Repository: "https://github.com/acme/skills",
				Ref:        "release",
				URL:        "https://axela.app/v1/catalogs/acme/acme",
			},
			publishers: func(_ *testing.T, existing string) []string { return []string{existing} },
			notaries:   func(_ *testing.T, existing string) []string { return []string{existing} },
			want:       "different repository, ref or catalog URL",
		},
		{
			name: "catalog url mismatch",
			catalog: enrollment.Catalog{
				Name:       "acme",
				Repository: "https://github.com/acme/skills",
				Ref:        "main",
				URL:        "https://axela.app/v1/catalogs/acme/other",
			},
			publishers: func(_ *testing.T, existing string) []string { return []string{existing} },
			notaries:   func(_ *testing.T, existing string) []string { return []string{existing} },
			want:       "different repository, ref or catalog URL",
		},
		{
			name: "publisher key mismatch",
			catalog: enrollment.Catalog{
				Name:       "acme",
				Repository: "https://github.com/acme/skills",
				Ref:        "main",
				URL:        "https://axela.app/v1/catalogs/acme/acme",
			},
			publishers: func(t *testing.T, _ string) []string {
				_, replacement := encodedConnectKey(t)
				return []string{replacement}
			},
			notaries: func(_ *testing.T, existing string) []string { return []string{existing} },
			want:     "already pins another key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SKILLTRUST_HOME", t.TempDir())

			publisherID, publisher := encodedConnectKey(t)
			notaryID, notary := encodedConnectKey(t)
			pinEncodedConnectKey(t, "catalog:acme", publisher)
			pinEncodedConnectKey(t, "notary:acme", notary)

			if err := saveBootstrapSubscriptionsFile([]Subscription{{
				Name:       "acme",
				Repository: "https://github.com/acme/skills",
				Ref:        "main",
				CatalogURL: "https://axela.app/v1/catalogs/acme/acme",
				KeyIDs:     []string{publisherID, notaryID},
				Threshold:  2,
				Parties: map[string][]string{
					"publisher": {publisherID},
					notaryParty: {notaryID},
				},
			}}); err != nil {
				t.Fatal(err)
			}

			beforeSubscriptions, err := os.ReadFile(subscriptionsPath())
			if err != nil {
				t.Fatal(err)
			}
			beforePins, err := os.ReadFile(defaultTrustedKeys())
			if err != nil {
				t.Fatal(err)
			}

			_, err = saveBootstrapSubscriptions(connectDefaultBaseURL, &enrollment.Connection{
				PublisherKeys: tc.publishers(t, publisher),
				NotaryKeys:    tc.notaries(t, notary),
				Catalogs:      []enrollment.Catalog{tc.catalog},
			})
			if err == nil {
				t.Fatal("conflicting bootstrap change was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err, tc.want)
			}

			afterSubscriptions, err := os.ReadFile(subscriptionsPath())
			if err != nil {
				t.Fatal(err)
			}
			if string(afterSubscriptions) != string(beforeSubscriptions) {
				t.Fatalf("subscription file changed on conflict:\n%s", string(afterSubscriptions))
			}
			afterPins, err := os.ReadFile(defaultTrustedKeys())
			if err != nil {
				t.Fatal(err)
			}
			if string(afterPins) != string(beforePins) {
				t.Fatalf("trusted keys changed on conflict:\n%s", string(afterPins))
			}
		})
	}
}

func TestEnsurePendingConnectKeepsTheSavedMachineLabelOnBareRerun(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	machinePublic, machinePrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), machinePrivate); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	pending := &pendingConnect{
		Version:      connectPendingVersion,
		Audience:     connectDefaultBaseURL,
		Machine:      "Roman laptop",
		MachineKeyID: attest.KeyID(machinePublic),
		Token:        strings.Repeat("ab", 32),
	}

	resumed, created, err := ensurePendingConnect(connectDefaultBaseURL, "", pending, now)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("bare rerun should reuse the saved pending request")
	}
	if resumed != pending {
		t.Fatal("ensurePendingConnect returned a different pending request")
	}
	if resumed.Machine != pending.Machine {
		t.Fatalf("machine = %q, want %q", resumed.Machine, pending.Machine)
	}
}

func TestResumeSavedConnectReusesSavedConnectionWithoutPrintingSecrets(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	machinePublic, machinePrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), machinePrivate); err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePublicKey(defaultPublicKey(), machinePublic); err != nil {
		t.Fatal(err)
	}

	token := strings.Repeat("ab", 32)
	if err := writeOwnerOnlyText(connectCredentialsPath(), token+"\n"); err != nil {
		t.Fatal(err)
	}
	writeExpiredPendingConnect(t, machinePrivate, token)

	current := &savedConnect{
		Version:      connectRecordVersion,
		Audience:     connectDefaultBaseURL,
		Organisation: "acme",
		Machine:      "Work laptop",
		MachineKeyID: attest.KeyID(machinePublic),
		IngestURL:    "https://axela.app/v1/events",
		DashboardURL: "https://axela.app/orgs/acme",
	}

	var pending *pendingConnect
	var connection *enrollment.Connection
	output := capture(t, func() {
		pending, connection, err = resumeSavedConnect(connectDefaultBaseURL, current)
	})
	if err != nil {
		t.Fatal(err)
	}
	if output != "" {
		t.Fatalf("resumeSavedConnect printed unexpectedly: %q", output)
	}
	if strings.Contains(output, token) {
		t.Fatal("resumeSavedConnect printed the local reporting credential")
	}
	if pending == nil || connection == nil {
		t.Fatal("resumeSavedConnect did not rebuild the saved connection")
	}
	if !pending.Resuming {
		t.Fatal("resumed connection should be marked as resuming")
	}
	if pending.Token != token {
		t.Fatalf("token = %q, want %q", pending.Token, token)
	}
	if pending.Machine != current.Machine || pending.MachineKeyID != current.MachineKeyID {
		t.Fatalf("pending = %#v, current = %#v", pending, current)
	}
	if connection.Organisation != current.Organisation || connection.MachineKeyID != current.MachineKeyID {
		t.Fatalf("connection = %#v, current = %#v", connection, current)
	}
	if connection.IngestURL != current.IngestURL || connection.DashboardURL != current.DashboardURL {
		t.Fatalf("connection endpoints = %#v, current = %#v", connection, current)
	}
}

func TestResumeSavedConnectRejectsInvalidSavedState(t *testing.T) {
	cases := []struct {
		name       string
		base       string
		mutate     func(*savedConnect)
		replaceKey bool
		want       string
	}{
		{
			name: "different base",
			base: "https://other.example",
			want: "already connected to",
		},
		{
			name: "unsupported version",
			base: connectDefaultBaseURL,
			mutate: func(current *savedConnect) {
				current.Version = 0
			},
			want: "format is not supported",
		},
		{
			name: "missing audience",
			base: connectDefaultBaseURL,
			mutate: func(current *savedConnect) {
				current.Audience = ""
			},
			want: "already connected to",
		},
		{
			name:       "mismatched local key",
			base:       connectDefaultBaseURL,
			replaceKey: true,
			want:       "no longer matches this computer's connection",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SKILLTRUST_HOME", t.TempDir())

			machinePublic, machinePrivate, err := attest.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := attest.WritePrivateKey(defaultSigningKey(), machinePrivate); err != nil {
				t.Fatal(err)
			}
			if err := attest.WritePublicKey(defaultPublicKey(), machinePublic); err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerOnlyText(connectCredentialsPath(), strings.Repeat("ab", 32)+"\n"); err != nil {
				t.Fatal(err)
			}

			current := &savedConnect{
				Version:      connectRecordVersion,
				Audience:     connectDefaultBaseURL,
				Organisation: "acme",
				Machine:      "Work laptop",
				MachineKeyID: attest.KeyID(machinePublic),
				IngestURL:    "https://axela.app/v1/events",
				DashboardURL: "https://axela.app/orgs/acme",
			}
			if tc.mutate != nil {
				tc.mutate(current)
			}
			if tc.replaceKey {
				otherPublic, otherPrivate, err := attest.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				if err := attest.WritePrivateKey(defaultSigningKey(), otherPrivate); err != nil {
					t.Fatal(err)
				}
				if err := attest.WritePublicKey(defaultPublicKey(), otherPublic); err != nil {
					t.Fatal(err)
				}
			}

			_, _, err = resumeSavedConnect(tc.base, current)
			if err == nil {
				t.Fatal("resumeSavedConnect accepted invalid saved state")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestOwnerOnlyWritesTightenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not reliable on Windows")
	}
	t.Setenv("SKILLTRUST_HOME", t.TempDir())

	if err := os.MkdirAll(Home(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(connectStatePath(), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(connectCredentialsPath(), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := saveHomeJSON(connectStatePath(), savedConnect{Version: connectRecordVersion, Audience: connectDefaultBaseURL}); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyText(connectCredentialsPath(), "new-token\n"); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{connectStatePath(), connectCredentialsPath()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, got)
		}
	}
}

func encodedConnectKey(t *testing.T) (string, string) {
	t.Helper()
	public, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := attest.EncodePublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return attest.KeyID(public), string(encoded)
}

func pinEncodedConnectKey(t *testing.T, label, encoded string) {
	t.Helper()
	key, err := parseConnectKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), label, key); err != nil {
		t.Fatal(err)
	}
}

func writeExpiredPendingConnect(t *testing.T, machineKey ed25519.PrivateKey, token string) {
	t.Helper()
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	request := enrollment.Request{
		Audience:    connectDefaultBaseURL,
		Nonce:       strings.Repeat("cd", 32),
		Machine:     "Work laptop",
		TokenDigest: secretDigest(token),
		IssuedAt:    now.Add(-enrollment.Lifetime),
		ExpiresAt:   now.Add(-time.Minute),
	}
	envelope, err := enrollment.Sign(request, machineKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveHomeJSON(pendingConnectPath(), pendingConnect{
		Version:     connectPendingVersion,
		Audience:    connectDefaultBaseURL,
		Machine:     request.Machine,
		Token:       token,
		Envelope:    envelope,
		RequestedAt: request.IssuedAt,
	}); err != nil {
		t.Fatal(err)
	}
}
