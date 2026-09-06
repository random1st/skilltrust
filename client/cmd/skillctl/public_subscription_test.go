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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
	publicsubscription "github.com/random1st/skilltrust/subscription"
)

type publicSubscriptionTransport func(*http.Request) (*http.Response, error)

func (f publicSubscriptionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type publicSubscriptionFixture struct {
	t            *testing.T
	r            publicSubscriptionResolver
	now          time.Time
	keyTime      time.Time
	repository   string
	publisher    ed25519.PrivateKey
	notaries     []ed25519.PrivateKey
	snapshot     catalog.Snapshot
	descriptor   publicsubscription.Descriptor
	catalogBytes []byte
	descriptorBy []byte
	keyBytes     []byte
	redirect     string
	mu           sync.Mutex
	requests     []string
	fetches      int
}

func newPublicSubscriptionFixture(t *testing.T) *publicSubscriptionFixture {
	t.Helper()
	t.Setenv("SKILLTRUST_HOME", filepath.Join(t.TempDir(), "state"))
	f := &publicSubscriptionFixture{t: t, now: time.Now().UTC().Truncate(time.Second), repository: filepath.Join(t.TempDir(), "repository")}
	f.keyTime = f.now
	capture(t, func() {
		if err := writeDemoMarketplace(f.repository); err != nil {
			t.Fatal(err)
		}
	})
	_, f.publisher, _ = attest.GenerateKey()
	_, notary, _ := attest.GenerateKey()
	f.notaries = []ed25519.PrivateKey{notary}
	manifest, err := marketplace.Load(f.repository)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := marketplace.Plan(f.repository, manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot = catalog.Snapshot{Version: 1, Name: "acme", Sequence: 3, IssuedAt: f.now.Add(-time.Minute), ValidUntil: f.now.Add(time.Hour), Skills: coverage.Signed}
	commit, err := exec.Command("git", "-C", f.repository, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := attest.EncodePublicKey(f.publisher.Public().(ed25519.PublicKey))
	f.descriptor = publicsubscription.Descriptor{Version: 1, Origin: publicsubscription.Origin, Organisation: "team", Catalog: "acme",
		Repository: "https://github.com/example/acme.git", Ref: "refs/heads/main", Commit: strings.TrimSpace(string(commit)),
		CatalogURL: publicsubscription.Origin + "/v1/catalogs/team/acme", PublisherKeys: []string{string(pem)},
		IssuedAt: f.now, ExpiresAt: f.now.Add(10 * time.Minute)}
	f.signCatalog(f.publisher, notary)
	f.signDescriptor(notary)
	f.signKeySet()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.URL.Path)
		f.mu.Unlock()
		if f.redirect != "" {
			w.Header().Set("Location", f.redirect)
			w.WriteHeader(http.StatusFound)
			return
		}
		switch r.URL.Path {
		case "/notary.pub":
			pem, _ := attest.EncodePublicKey(f.notaries[0].Public().(ed25519.PublicKey))
			w.Write(pem)
		case "/v1/keys":
			w.Write(f.keyBytes)
		case "/v1/subscriptions/team/acme":
			w.Write(f.descriptorBy)
		case "/v1/catalogs/team/acme":
			w.Write(f.catalogBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	endpoint, _ := url.Parse(server.URL)
	underlying := server.Client().Transport
	transport := publicSubscriptionTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" || request.URL.Host != "axela.app" {
			t.Errorf("unexpected network destination %q", request.URL.String())
			return nil, fmt.Errorf("fixture refuses every non-Axela URL")
		}
		copy := request.Clone(request.Context())
		copy.URL.Scheme, copy.URL.Host = endpoint.Scheme, endpoint.Host
		return underlying.RoundTrip(copy)
	})
	f.r = newPublicSubscriptionResolver()
	f.r.client.Transport = transport
	f.r.now = func() time.Time { return f.now }
	f.r.fetch = func(ctx context.Context, root, name, repository, ref string) (source.Source, error) {
		f.fetches++
		if repository != "https://github.com/example/acme.git" || ref != "main" {
			return source.Source{}, fmt.Errorf("unexpected repository fetch")
		}
		return source.FetchContext(ctx, root, name, f.repository, ref)
	}
	return f
}

func (f *publicSubscriptionFixture) signCatalog(keys ...ed25519.PrivateKey) {
	f.t.Helper()
	// Sign exact fixture bytes, including deliberately invalid snapshots.
	payload, err := json.Marshal(f.snapshot)
	if err != nil || len(keys) == 0 {
		f.t.Fatal("cannot sign fixture catalog")
	}
	envelope := attest.SignPayload(catalog.PayloadType, payload, keys[0])
	for _, key := range keys[1:] {
		if err := attest.Countersign(envelope, key); err != nil {
			f.t.Fatal(err)
		}
	}
	f.catalogBytes, _ = json.MarshalIndent(envelope, "", "  ")
	sum := sha256.Sum256(f.catalogBytes)
	f.descriptor.CatalogDigest = hex.EncodeToString(sum[:])
}

func (f *publicSubscriptionFixture) signDescriptor(key ed25519.PrivateKey) {
	payload, _ := json.Marshal(f.descriptor)
	f.descriptorBy, _ = json.Marshal(attest.SignPayload(publicsubscription.PayloadType, payload, key))
}

func (f *publicSubscriptionFixture) signKeySet() {
	envelope, err := attest.SignKeySet(f.notaries, f.keyTime)
	if err != nil {
		f.t.Fatal(err)
	}
	f.keyBytes, _ = json.Marshal(envelope)
}

func publicStateBytes(t *testing.T) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	err := filepath.WalkDir(Home(), func(path string, entry fs.DirEntry, err error) error {
		if os.IsNotExist(err) && path == Home() {
			return nil
		}
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(Home(), path)
		result[relative] = body
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPublicSubscriptionNewUserThenDoctor(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	previousFactory, previousArgs := newPublicSubscriptionResolver, os.Args
	newPublicSubscriptionResolver = func() publicSubscriptionResolver { return f.r }
	os.Args = []string{"axela"}
	t.Cleanup(func() { newPublicSubscriptionResolver, os.Args = previousFactory, previousArgs })
	output, code := captureStdout(t, func() int { return runSubscribe([]string{"axela://team/acme"}) })
	if code != exitClean || !strings.Contains(output, "Following axela://team/acme: 1 signed plugin") || !strings.Contains(output, "Run: axela doctor") {
		t.Fatalf("public subscribe failed: code=%d output=%s", code, output)
	}
	if strings.Contains(output, "connected") || strings.Contains(output, "receipt") {
		t.Fatal("a local subscription claimed cloud connection or receipt")
	}
	for _, path := range []string{connectStatePath(), pendingConnectPath(), connectCredentialsPath(), connectStatusPath(), reportConfigPath(), latestCheckPath(CheckScopeManaged)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("subscription created unexpected account or reporting state at %s", filepath.Base(path))
		}
	}
	private, err := attest.LoadPrivateKey(defaultSigningKey())
	if err != nil {
		t.Fatal("subscription did not prepare the local check signer")
	}
	public, err := attest.LoadPublicKey(defaultPublicKey())
	if err != nil || !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("the local check signer is not a matching pair")
	}
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	previousAgents, previousTransport := agents, http.DefaultTransport
	agents, http.DefaultTransport = []agent{known}, f.r.client.Transport
	t.Cleanup(func() { agents, http.DefaultTransport = previousAgents, previousTransport })
	client := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", client)
	capture(t, func() {
		if code := installDemoPlugin(f.repository, client); code != exitClean {
			t.Fatal("fixture installation failed")
		}
	})
	output, code = captureStdout(t, func() int { return runDoctor([]string{"--json"}) })
	var verdict machineStatus
	if err := json.Unmarshal([]byte(output), &verdict); err != nil {
		t.Fatalf("doctor did not return JSON: %v", err)
	}
	// With no hook installed the status may still need attention; the signed
	// current check must nevertheless describe the real installed bytes.
	if code != exitClean && code != exitFindings || verdict.ReportAccepted || verdict.LastCheck == nil || !verdict.LastCheck.Complete || verdict.LastCheck.Checked != 1 || !verdict.LastCheck.Healthy() {
		t.Fatalf("doctor did not report the verified local install: code=%d status=%s", code, verdict.Status)
	}
	if _, err := os.Lstat(known.HookConfigPath()); !os.IsNotExist(err) {
		t.Fatal("public subscribe or doctor installed hooks")
	}
}

func TestPublicSubscriptionRejectsTamperingWithoutSaving(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*publicSubscriptionFixture)
	}{
		{"descriptor_bad_signature", func(f *publicSubscriptionFixture) { _, other, _ := attest.GenerateKey(); f.signDescriptor(other) }},
		{"descriptor_expired", func(f *publicSubscriptionFixture) { f.descriptor.ExpiresAt = f.now; f.signDescriptor(f.notaries[0]) }},
		{"descriptor_other_origin", func(f *publicSubscriptionFixture) {
			f.descriptor.Origin = "https://attacker.example"
			f.signDescriptor(f.notaries[0])
		}},
		{"descriptor_other_catalog", func(f *publicSubscriptionFixture) { f.descriptor.Catalog = "other"; f.signDescriptor(f.notaries[0]) }},
		{"descriptor_catalog_redirect", func(f *publicSubscriptionFixture) {
			f.descriptor.CatalogURL = "https://attacker.example/catalog"
			f.signDescriptor(f.notaries[0])
		}},
		{"descriptor_repository_redirect", func(f *publicSubscriptionFixture) {
			f.descriptor.Repository = "https://attacker.example/repo.git"
			f.signDescriptor(f.notaries[0])
		}},
		{"descriptor_too_large", func(f *publicSubscriptionFixture) {
			f.descriptorBy = bytes.Repeat([]byte(" "), publicsubscription.MaxBytes+1)
		}},
		{"catalog_bytes_changed", func(f *publicSubscriptionFixture) { f.catalogBytes = append(f.catalogBytes, '\n') }},
		{"catalog_no_publisher", func(f *publicSubscriptionFixture) { f.signCatalog(f.notaries...); f.signDescriptor(f.notaries[0]) }},
		{"catalog_no_notary", func(f *publicSubscriptionFixture) { f.signCatalog(f.publisher); f.signDescriptor(f.notaries[0]) }},
		{"catalog_expired", func(f *publicSubscriptionFixture) {
			f.snapshot.ValidUntil = f.now
			f.signCatalog(f.publisher, f.notaries[0])
			f.signDescriptor(f.notaries[0])
		}},
		{"catalog_wrong_name", func(f *publicSubscriptionFixture) {
			f.snapshot.Name = "other"
			f.signCatalog(f.publisher, f.notaries[0])
			f.signDescriptor(f.notaries[0])
		}},
		{"catalog_zero_sequence", func(f *publicSubscriptionFixture) {
			f.snapshot.Sequence = 0
			f.signCatalog(f.publisher, f.notaries[0])
			f.signDescriptor(f.notaries[0])
		}},
		{"descriptor_outlives_catalog", func(f *publicSubscriptionFixture) {
			f.snapshot.ValidUntil = f.now.Add(time.Minute)
			f.signCatalog(f.publisher, f.notaries[0])
			f.signDescriptor(f.notaries[0])
		}},
		{"source_commit_moved", func(f *publicSubscriptionFixture) {
			f.descriptor.Commit = strings.Repeat("0", 40)
			f.signDescriptor(f.notaries[0])
		}},
		{"source_digest_changed", func(f *publicSubscriptionFixture) {
			f.snapshot.Skills[0].Digest = "sha256:" + strings.Repeat("0", 64)
			f.signCatalog(f.publisher, f.notaries[0])
			f.signDescriptor(f.notaries[0])
		}},
		{"publisher_notary_same_key", func(f *publicSubscriptionFixture) {
			pem, _ := attest.EncodePublicKey(f.notaries[0].Public().(ed25519.PublicKey))
			f.descriptor.PublisherKeys = []string{string(pem)}
			f.signDescriptor(f.notaries[0])
		}},
		{"publisher_not_actual_signer", func(f *publicSubscriptionFixture) {
			pub, _, _ := attest.GenerateKey()
			pem, _ := attest.EncodePublicKey(pub)
			f.descriptor.PublisherKeys = append(f.descriptor.PublisherKeys, string(pem))
			f.signDescriptor(f.notaries[0])
		}},
		{"keyset_future", func(f *publicSubscriptionFixture) { f.keyTime = f.now.Add(6 * time.Minute); f.signKeySet() }},
		{"keyset_stale", func(f *publicSubscriptionFixture) { f.keyTime = f.now.Add(-25 * time.Hour); f.signKeySet() }},
		{"http_redirect", func(f *publicSubscriptionFixture) { f.redirect = "https://attacker.example" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newPublicSubscriptionFixture(t)
			test.mutate(f)
			before := publicStateBytes(t)
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
				t.Fatal("tampered public subscription was accepted")
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("failed verification changed subscription state or pinned keys")
			}
		})
	}
}

func TestPublicSubscriptionURIAndManualFlagsMakeNoRequests(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	for _, raw := range []string{"axela://evil.example/acme", "axela://team:443/acme", "axela://user@team/acme", "axela://team/acme?x=1", "axela://team/acme#x", "axela://team/%61cme", "axela://team/../acme", "AXELA://team/acme", "axela://team/acme/", "axela:team/acme"} {
		if _, _, err := f.r.subscribe(context.Background(), raw); err == nil {
			t.Fatalf("accepted malformed URI %q", raw)
		}
	}
	previous := newPublicSubscriptionResolver
	newPublicSubscriptionResolver = func() publicSubscriptionResolver { return f.r }
	t.Cleanup(func() { newPublicSubscriptionResolver = previous })
	if code := runSubscribe([]string{"axela://team/acme", "--threshold", "1"}); code != exitUsage {
		t.Fatal("a URI accepted a weaker manual threshold")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 || f.fetches != 0 {
		t.Fatal("malformed URI or manual override caused a network request")
	}
}

func TestPublicSubscriptionWriteFailureRollsBackPinsAndLocalSigner(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			f := newPublicSubscriptionFixture(t)
			if existing {
				if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
					t.Fatal(err)
				}
			}
			before := publicStateBytes(t)
			f.r.rename = func(from, to string) error {
				if to == defaultTrustedKeys() {
					return errors.New("fixture pin commit failure")
				}
				return os.Rename(from, to)
			}
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil || !strings.Contains(err.Error(), "fixture pin commit failure") {
				t.Fatal("pin commit failure was not reported")
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("pin commit failure did not restore the previous state and identity bytes")
			}
		})
	}
}

func TestPublicSubscriptionResubscribeKeepsIdentityAndRotatesNotaryByProof(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
		t.Fatal(err)
	}
	identityBefore, err := os.ReadFile(defaultSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	// Pending account consent is unrelated to choosing a public publisher.
	pending := []byte(`{"owned":"pending approval must remain byte exact"}`)
	if err := os.WriteFile(pendingConnectPath(), pending, 0o600); err != nil {
		t.Fatal(err)
	}
	old := f.notaries[0]
	_, incoming, _ := attest.GenerateKey()
	for _, keys := range [][]ed25519.PrivateKey{{old}, {old, incoming}, {incoming}} {
		f.now = f.now.Add(time.Second)
		f.keyTime = f.now
		f.notaries = keys
		f.descriptor.IssuedAt, f.descriptor.ExpiresAt = f.now, f.now.Add(10*time.Minute)
		f.signKeySet()
		f.signCatalog(append([]ed25519.PrivateKey{f.publisher}, keys...)...)
		f.signDescriptor(keys[0])
		if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
			t.Fatalf("signed notary rotation or repeat subscription failed: %v", err)
		}
		identityAfter, err := os.ReadFile(defaultSigningKey())
		if err != nil || !bytes.Equal(identityBefore, identityAfter) {
			t.Fatal("re-subscribe replaced the machine identity")
		}
		pendingAfter, err := os.ReadFile(pendingConnectPath())
		if err != nil || !bytes.Equal(pending, pendingAfter) {
			t.Fatal("re-subscribe changed pending account approval")
		}
	}
	subs, err := loadSubscriptions()
	if err != nil || len(subs) != 1 || len(subs[0].Parties[notaryParty]) != 2 || subs[0].Required() != 2 || subs[0].CatalogName != "acme" {
		t.Fatal("notary overlap lost its one-party grouping or catalog identity")
	}
	// The documented final retirement step removes labels from the trust
	// store. Old subscription IDs must not force a fresh TOFU or re-pin them.
	pins, err := attest.PinnedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	for label, key := range pins {
		if attest.KeyID(key) == attest.KeyID(old.Public().(ed25519.PublicKey)) {
			if err := attest.UnpinKey(defaultTrustedKeys(), label); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.now = f.now.Add(time.Second)
	f.keyTime = f.now
	f.signKeySet()
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
		t.Fatalf("re-subscribe after explicit notary retirement failed: %v", err)
	}
	subs, err = loadSubscriptions()
	if err != nil || len(subs[0].Parties[notaryParty]) != 1 || subs[0].Parties[notaryParty][0] != attest.KeyID(incoming.Public().(ed25519.PublicKey)) {
		t.Fatal("re-subscribe restored the retired notary pin")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	firstFetches := 0
	for _, path := range f.requests {
		if path == "/notary.pub" {
			firstFetches++
		}
	}
	if firstFetches != 1 {
		t.Fatal("re-subscription restarted notary trust on first use")
	}
}

func TestPublicSubscriptionRefusesExistingTrustAndSourceConflicts(t *testing.T) {
	for _, scenario := range []string{"repository", "ref", "catalog_url", "catalog_identity", "publisher", "threshold", "rollback", "notary_replaced", "keyset_replay", "keyset_equal_addition"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPublicSubscriptionFixture(t)
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
				t.Fatal(err)
			}
			subs, err := loadSubscriptions()
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "repository":
				subs[0].Repository = "https://github.com/other/acme.git"
			case "ref":
				subs[0].Ref = "refs/heads/other"
			case "catalog_url":
				subs[0].CatalogURL = publicsubscription.Origin + "/v1/catalogs/other/acme"
			case "catalog_identity":
				subs[0].CatalogName = "other"
			case "publisher":
				pub, other, _ := attest.GenerateKey()
				f.publisher = other
				pem, _ := attest.EncodePublicKey(pub)
				f.descriptor.PublisherKeys = []string{string(pem)}
				f.signCatalog(other, f.notaries[0])
				f.signDescriptor(f.notaries[0])
			case "threshold":
				subs[0].Threshold = 3
			case "rollback":
				f.snapshot.Sequence--
				f.signCatalog(f.publisher, f.notaries[0])
				f.signDescriptor(f.notaries[0])
			case "notary_replaced":
				_, other, _ := attest.GenerateKey()
				f.notaries = []ed25519.PrivateKey{other}
				f.signKeySet()
				f.signCatalog(f.publisher, other)
				f.signDescriptor(other)
			case "keyset_replay":
				f.keyTime = f.keyTime.Add(-time.Second)
				f.signKeySet()
			case "keyset_equal_addition":
				_, incoming, _ := attest.GenerateKey()
				f.notaries = append(f.notaries, incoming)
				f.signKeySet()
			}
			if err := saveSubscriptions(subs); err != nil {
				t.Fatal(err)
			}
			before := publicStateBytes(t)
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
				t.Fatalf("accepted existing %s conflict", scenario)
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("failed re-subscription changed existing trust, sequence, identity or source")
			}
		})
	}
}

func TestPublicSubscriptionNameRemainsBoundDuringLaterChecks(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
		t.Fatal(err)
	}
	subs, err := loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.Name = "another-catalog"
	f.signCatalog(f.publisher, f.notaries[0])
	if err := os.WriteFile(indexPath(subs[0]), f.catalogBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshotOnly(subs[0], trusted, f.now); err == nil {
		t.Fatal("a later check accepted a catalog-name substitution")
	}
	// Joining a team later must keep the public descriptor's identity binding.
	incoming := subs[0]
	incoming.CatalogName = ""
	merged, err := mergeBootstrapSubscription(subs[0], incoming)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshotOnly(merged, trusted, f.now); err == nil {
		t.Fatal("account bootstrap removed the public subscription's catalog-name binding")
	}
}

func TestPublicSubscriptionPreservesUnusableIdentityAndSymlinkedState(t *testing.T) {
	for _, scenario := range []string{"partial_private", "partial_public", "malformed", "mismatch", "key_symlink", "pins_symlink", "state_parent_symlink"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPublicSubscriptionFixture(t)
			if err := os.MkdirAll(Home(), 0o700); err != nil {
				t.Fatal(err)
			}
			public, private, _ := attest.GenerateKey()
			ownedTarget := filepath.Join(t.TempDir(), "preserved")
			if err := os.WriteFile(ownedTarget, []byte("preserved owned fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "partial_private":
				if err := attest.WritePrivateKey(defaultSigningKey(), private); err != nil {
					t.Fatal(err)
				}
			case "partial_public":
				if err := attest.WritePublicKey(defaultPublicKey(), public); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(defaultSigningKey(), []byte("malformed owned key fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := attest.WritePublicKey(defaultPublicKey(), public); err != nil {
					t.Fatal(err)
				}
			case "mismatch":
				other, _, _ := attest.GenerateKey()
				if err := attest.WritePrivateKey(defaultSigningKey(), private); err != nil {
					t.Fatal(err)
				}
				if err := attest.WritePublicKey(defaultPublicKey(), other); err != nil {
					t.Fatal(err)
				}
			case "key_symlink":
				if err := os.Symlink(ownedTarget, defaultSigningKey()); err != nil {
					t.Skip(err)
				}
			case "pins_symlink":
				if err := os.WriteFile(ownedTarget, []byte(`{"version":1,"keys":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(ownedTarget, defaultTrustedKeys()); err != nil {
					t.Skip(err)
				}
			case "state_parent_symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(Home(), "state")); err != nil {
					t.Skip(err)
				}
			}
			before, targetBefore := publicStateBytes(t), []byte(nil)
			targetBefore, err := os.ReadFile(ownedTarget)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
				t.Fatal("unusable identity or symlinked state was accepted")
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("unusable identity or symlinked state was changed")
			}
			targetAfter, err := os.ReadFile(ownedTarget)
			if err != nil || !bytes.Equal(targetBefore, targetAfter) {
				t.Fatal("a symlink target was changed")
			}
		})
	}
}
