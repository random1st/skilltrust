package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/enrollment"
	"github.com/random1st/skilltrust/internal/marketplace"
	publicsubscription "github.com/random1st/skilltrust/subscription"
)

type teamSubscriptionFixture struct {
	*publicSubscriptionFixture
	payload                  []byte
	machine                  ed25519.PrivateKey
	token                    string
	denied                   map[string]bool
	offline                  bool
	redirectPath, redirectTo string
	approvedOrg              string
	waiting                  bool
	authenticated            []string
	approvalRequests         int
	beforeResponse           func(string)
}

func newTeamSubscriptionFixture(t *testing.T, connected bool) *teamSubscriptionFixture {
	t.Helper()
	f := &teamSubscriptionFixture{publicSubscriptionFixture: newPublicSubscriptionFixture(t),
		denied: map[string]bool{}, token: strings.Repeat("a", 64), approvedOrg: "team"}
	var digest string
	var err error
	f.payload, digest, err = publicsubscription.BuildSource(f.repository)
	if err != nil {
		t.Fatal(err)
	}
	f.descriptor.Access, f.descriptor.SourceDigest = "team", digest
	f.descriptor.SourceURL, err = publicsubscription.SourceURL("team", "acme", f.descriptor.CatalogDigest)
	if err != nil {
		t.Fatal(err)
	}
	f.signDescriptor(f.notaries[0])
	if connected {
		f.connect(t)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := request.URL.Path
		f.requests = append(f.requests, path)
		if path == "/notary.pub" || path == "/v1/keys" {
			if request.Header.Get("Authorization") != "" || request.Header.Get(publicsubscription.ReadProofHeader) != "" {
				t.Error("credential or read proof leaked to a key discovery endpoint")
			}
			if path == "/v1/keys" {
				w.Write(f.keyBytes)
			} else {
				pem, _ := attest.EncodePublicKey(f.notaries[0].Public().(ed25519.PublicKey))
				w.Write(pem)
			}
			return
		}
		if path == "/v1/connect/status" {
			f.approvalRequests++
			var envelope attest.Envelope
			if json.NewDecoder(request.Body).Decode(&envelope) != nil {
				t.Error("unreadable enrollment")
				w.WriteHeader(400)
				return
			}
			proof, keyID, err := enrollment.Verify(&envelope, publicsubscription.Origin, f.now)
			if err != nil || proof.Organisation != "team" || proof.TokenDigest != secretDigest(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")) {
				t.Error("enrollment was not bound to the requested team and token")
				w.WriteHeader(403)
				return
			}
			f.token = strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
			f.machine, err = attest.LoadPrivateKey(defaultSigningKey())
			if err != nil {
				t.Error(err)
				w.WriteHeader(403)
				return
			}
			if f.waiting {
				w.WriteHeader(202)
				return
			}
			json.NewEncoder(w).Encode(enrollment.Connection{Organisation: f.approvedOrg, MachineKeyID: keyID,
				IngestURL: publicsubscription.Origin + "/v1/ingest", DashboardURL: publicsubscription.Origin + "/app/" + f.approvedOrg,
				// Deliberately unrelated bootstrap material must not be followed by subscribe.
				Catalogs: []enrollment.Catalog{{Name: "unrelated", Repository: "https://github.com/example/unrelated.git", URL: publicsubscription.Origin + "/v1/catalogs/team/unrelated"}}})
			return
		}
		if request.Header.Get("Authorization") == "" {
			w.WriteHeader(404)
			return
		}
		if len(f.machine) == 0 || request.Header.Get("Authorization") != "Bearer "+f.token ||
			publicsubscription.VerifyRead(request.Header.Get(publicsubscription.ReadProofHeader), request.Method,
				publicsubscription.Origin+request.URL.RequestURI(), attest.NewTrustedKeys(f.machine.Public().(ed25519.PublicKey)), f.now) != nil {
			t.Error("private read lacked its exact machine token and signed request")
			w.WriteHeader(403)
			return
		}
		f.authenticated = append(f.authenticated, path)
		if f.denied[path] {
			w.WriteHeader(403)
			return
		}
		if path == f.redirectPath {
			w.Header().Set("Location", f.redirectTo)
			w.WriteHeader(302)
			return
		}
		if f.beforeResponse != nil {
			f.beforeResponse(path)
		}
		switch {
		case path == "/v1/subscriptions/team/acme":
			w.Write(f.descriptorBy)
		case path == "/v1/catalogs/team/acme":
			w.Write(f.catalogBytes)
		case publicsubscription.Origin+path == f.descriptor.SourceURL:
			w.Write(f.payload)
		default:
			t.Errorf("unexpected authenticated route %q", path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	endpoint, _ := url.Parse(server.URL)
	underlying := server.Client().Transport
	f.r.client.Transport = publicSubscriptionTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" || request.URL.Host != "axela.app" {
			t.Errorf("network escaped Axela: %q", request.URL.String())
			return nil, fmt.Errorf("forbidden fixture route")
		}
		if f.offline {
			return nil, fmt.Errorf("fixture network unavailable")
		}
		copy := request.Clone(request.Context())
		copy.URL.Scheme, copy.URL.Host = endpoint.Scheme, endpoint.Host
		return underlying.RoundTrip(copy)
	})
	previousFactory := newPublicSubscriptionResolver
	newPublicSubscriptionResolver = func() publicSubscriptionResolver { return f.r }
	t.Cleanup(func() { newPublicSubscriptionResolver = previousFactory })
	return f
}

func (f *teamSubscriptionFixture) connect(t *testing.T) {
	t.Helper()
	key, public, _, err := ensureSigningKey("owned test computer")
	if err != nil {
		t.Fatal(err)
	}
	f.machine = key
	if err := writeOwnerOnlyText(connectCredentialsPath(), f.token+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := saveHomeJSON(connectStatePath(), savedConnect{Version: connectRecordVersion, Audience: publicsubscription.Origin,
		Organisation: "team", Machine: connectMachine(""), MachineKeyID: attest.KeyID(public), IngestURL: publicsubscription.Origin + "/v1/ingest",
		DashboardURL: publicsubscription.Origin + "/app/team", ConnectedAt: f.now, IdentityOnly: true}); err != nil {
		t.Fatal(err)
	}
}

func (f *teamSubscriptionFixture) subscribeTeam(t *testing.T) {
	t.Helper()
	count, uncovered, err := f.r.subscribe(context.Background(), "axela://team/acme")
	if err != nil || count != 1 || uncovered != 0 {
		t.Fatalf("team subscribe: %d/%d %v", count, uncovered, err)
	}
	if f.fetches != 0 {
		t.Fatal("team source invoked Git")
	}
}

func TestTeamSubscriptionConnectedMemberUsesOnlyAuthenticatedAxelaSource(t *testing.T) {
	f := newTeamSubscriptionFixture(t, true)
	beforeConnection, _ := os.ReadFile(connectStatePath())
	f.subscribeTeam(t)
	subscriptions, _ := loadSubscriptions()
	if len(subscriptions) != 1 || subscriptions[0].Access != "team" || subscriptions[0].AxelaURI != "axela://team/acme" {
		t.Fatalf("missing access binding: %+v", subscriptions)
	}
	if !reflect.DeepEqual(f.authenticated, []string{"/v1/subscriptions/team/acme", "/v1/catalogs/team/acme", strings.TrimPrefix(f.descriptor.SourceURL, publicsubscription.Origin)}) {
		t.Fatalf("not all private reads were authenticated: %v", f.authenticated)
	}
	if f.approvalRequests != 0 {
		t.Fatal("matching saved connection reopened browser enrollment")
	}
	afterConnection, _ := os.ReadFile(connectStatePath())
	if !bytes.Equal(beforeConnection, afterConnection) {
		t.Fatal("subscribe changed existing connection")
	}
	manifest, loadErr := marketplace.Load(filepath.Join(Home(), "sources", "acme"))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	plugin, local := manifest.Plugins[0].LocalPath(filepath.Join(Home(), "sources", "acme"))
	if !local {
		t.Fatal("archive lost native local plugin source")
	}
	got, err := os.ReadFile(filepath.Join(plugin, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	original, _ := manifest.Plugins[0].LocalPath(f.repository)
	want, err := os.ReadFile(filepath.Join(original, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("source extraction changed signed bytes")
	}
	for _, path := range []string{reportConfigPath(), connectStatusPath(), latestCheckPath(CheckScopeManaged)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("subscribe created reporting/check state: %s", path)
		}
	}
}

func TestTeamSubscriptionScopedConsentStoresOnlyIdentityAndRequestedCatalog(t *testing.T) {
	for _, validCatalog := range []bool{true, false} {
		t.Run(fmt.Sprint(validCatalog), func(t *testing.T) {
			f := newTeamSubscriptionFixture(t, false)
			if !validCatalog {
				f.payload[len(f.payload)/2] ^= 1
			}
			output, _ := captureStdout(t, func() int { return runPublicSubscribe("axela://team/acme") })
			current, err := loadSavedConnect()
			if err != nil || current == nil || !current.IdentityOnly || current.Organisation != "team" {
				t.Fatalf("consented identity missing: %+v %v", current, err)
			}
			pending, err := loadPendingConnect(f.now)
			if err != nil || pending == nil {
				t.Fatal("consent request was lost")
			}
			if strings.Contains(output, f.token) {
				t.Fatal("credential printed")
			}
			subscriptions, _ := loadSubscriptions()
			if validCatalog && (len(subscriptions) != 1 || subscriptions[0].Name != "acme") || !validCatalog && len(subscriptions) != 0 {
				t.Fatalf("unverified/unrelated catalog saved: %+v", subscriptions)
			}
			for _, path := range []string{reportConfigPath(), connectStatusPath(), latestCheckPath(CheckScopeManaged)} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("identity-only enrollment created %s", path)
				}
			}
		})
	}
}

func TestTeamSubscriptionDeniedOrOfflineCannotUsePopulatedCache(t *testing.T) {
	for _, mode := range []string{"descriptor", "catalog", "source", "network", "offline"} {
		t.Run(mode, func(t *testing.T) {
			f := newTeamSubscriptionFixture(t, true)
			f.subscribeTeam(t)
			client := filepath.Join(t.TempDir(), "claude")
			manifest, _ := marketplace.Load(filepath.Join(Home(), "sources", "acme"))
			plugin, _ := manifest.Plugins[0].LocalPath(filepath.Join(Home(), "sources", "acme"))
			installed := marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0")
			copyTree(t, installed, plugin)
			skillPath := filepath.Join(installed, "SKILL.md")
			changed := []byte("an intentional local change\n")
			if err := os.WriteFile(skillPath, changed, 0600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "descriptor":
				f.denied["/v1/subscriptions/team/acme"] = true
			case "catalog":
				f.denied["/v1/catalogs/team/acme"] = true
			case "source":
				f.denied[strings.TrimPrefix(f.descriptor.SourceURL, publicsubscription.Origin)] = true
			case "network":
				f.offline = true
			}
			before := publicStateBytes(t)
			check, code := RunManagedCheck(client, ManagedCheckOptions{Restore: true, UpdateSource: true, Offline: mode == "offline"})
			if code != exitClean || check.Complete || len(check.Results) != 0 || len(check.Unusable) != 1 || check.Catalogs[0].UsedCached {
				t.Fatalf("revoked/offline cached green: %+v, %d", check, code)
			}
			got, _ := os.ReadFile(skillPath)
			if !bytes.Equal(got, changed) {
				t.Fatal("denial restored a user's edit")
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("failed auth changed saved source, sequence, identity, or pins")
			}
			if mode == "offline" {
				f.offline = true
			}
			var hookOutput, hookDiagnostic bytes.Buffer
			hookCode := runHookPreSkillTo([]string{"--claude-home", client}, strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"deploy-runbook:run"}}`), &hookOutput, &hookDiagnostic)
			if hookCode != exitDeny {
				t.Fatalf("revoked/offline pre-skill was allowed: %d %s", hookCode, hookDiagnostic.String())
			}
			got, _ = os.ReadFile(skillPath)
			if !bytes.Equal(got, changed) {
				t.Fatal("pre-skill restored after denied access")
			}
			known, _ := lookupAgent("claude")
			stubNativeInstall(t, func(string) (string, error) { t.Fatal("denial called native lookup"); return "", nil }, func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("denial called native install")
				return nil, nil
			})
			if err := ensureFirstManagedPlugin(known); err == nil {
				t.Fatal("revoked/offline install succeeded from populated source")
			}
		})
	}
}

func TestTeamSubscriptionWrongTeamAndPendingConsentArePreserved(t *testing.T) {
	for _, mode := range []string{"saved_team", "saved_origin", "unscoped_pending", "other_pending", "unsafe_token", "partial_signer"} {
		t.Run(mode, func(t *testing.T) {
			connected := strings.HasPrefix(mode, "saved") || mode == "unsafe_token"
			f := newTeamSubscriptionFixture(t, connected)
			switch mode {
			case "saved_team", "saved_origin":
				current, _ := loadSavedConnect()
				if mode == "saved_team" {
					current.Organisation = "other"
				} else {
					current.Audience = "https://other.example"
				}
				if err := saveHomeJSON(connectStatePath(), current); err != nil {
					t.Fatal(err)
				}
			case "unscoped_pending", "other_pending":
				org := ""
				if mode == "other_pending" {
					org = "other"
				}
				if _, _, err := createPendingConnectFor(publicsubscription.Origin, "test", org, f.now); err != nil {
					t.Fatal(err)
				}
			case "unsafe_token":
				original := filepath.Join(t.TempDir(), "owned-token")
				if err := os.Rename(connectCredentialsPath(), original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, connectCredentialsPath()); err != nil {
					t.Fatal(err)
				}
			case "partial_signer":
				if err := os.MkdirAll(Home(), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(defaultPublicKey(), []byte("keep this partial identity"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := publicStateBytes(t)
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
				t.Fatal("wrong or unsafe identity was accepted")
			}
			if len(f.authenticated) != 0 || f.approvalRequests != 0 || !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("mismatching identity leaked a credential or replaced saved consent")
			}
		})
	}
}

func TestTeamSubscriptionWrongBrowserTeamCannotStoreAConnection(t *testing.T) {
	f := newTeamSubscriptionFixture(t, false)
	f.approvedOrg = "other"
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil || !strings.Contains(err.Error(), "different team") {
		t.Fatalf("wrong-team approval accepted: %v", err)
	}
	for _, path := range []string{connectStatePath(), connectCredentialsPath(), subscriptionsPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("wrong team created %s", path)
		}
	}
	pending, err := loadPendingConnect(f.now)
	if err != nil || pending == nil {
		t.Fatal("wrong-team response lost pending consent")
	}
	request, _, _, err := readPendingRequest(pending.Envelope, f.now)
	if err != nil || request.Organisation != "team" {
		t.Fatal("wrong-team response changed signed team scope")
	}
}

func TestTeamSubscriptionPendingApprovalResumesTheSameProof(t *testing.T) {
	f := newTeamSubscriptionFixture(t, false)
	f.waiting = true
	oldNow, oldSleep, oldOpen := connectNow, connectSleep, connectOpenBrowser
	now := f.now
	connectNow = func() time.Time { return now }
	connectSleep = func(time.Duration) { now = now.Add(connectDefaultWait + time.Second) }
	connectOpenBrowser = func(string) error { return nil }
	t.Cleanup(func() { connectNow, connectSleep, connectOpenBrowser = oldNow, oldSleep, oldOpen })
	_, code := captureStdout(t, func() int { return runPublicSubscribe("axela://team/acme") })
	if code != exitFindings {
		t.Fatalf("pending approval was reported as complete/error: %d", code)
	}
	before, _ := os.ReadFile(pendingConnectPath())
	f.waiting = false
	f.subscribeTeam(t)
	after, _ := os.ReadFile(pendingConnectPath())
	if !bytes.Equal(before, after) {
		t.Fatal("resuming private subscribe replaced the browser proof/token")
	}
}

func TestTeamSubscriptionTamperingNeverPromotesSourceOrPins(t *testing.T) {
	for _, mode := range []string{"source_bytes", "source_digest", "source_origin", "source_catalog", "publisher", "notary", "expired", "catalog_digest", "catalog_name", "access_downgrade"} {
		t.Run(mode, func(t *testing.T) {
			f := newTeamSubscriptionFixture(t, true)
			f.subscribeTeam(t)
			switch mode {
			case "source_bytes":
				f.payload[len(f.payload)/2] ^= 1
			case "source_digest":
				f.descriptor.SourceDigest = "sha256:" + strings.Repeat("0", 64)
			case "source_origin":
				f.descriptor.SourceURL = "https://attacker.example/source"
			case "source_catalog":
				f.descriptor.SourceURL, _ = publicsubscription.SourceURL("team", "other", f.descriptor.CatalogDigest)
			case "publisher":
				f.signCatalog(f.notaries...)
			case "notary":
				f.signCatalog(f.publisher)
			case "expired":
				f.descriptor.ExpiresAt = f.now
			case "catalog_digest":
				f.catalogBytes = append(f.catalogBytes, '\n')
			case "catalog_name":
				f.snapshot.Name = "other"
				f.signCatalog(f.publisher, f.notaries[0])
			case "access_downgrade":
				f.descriptor.Access, f.descriptor.SourceURL, f.descriptor.SourceDigest = "", "", ""
			}
			f.signDescriptor(f.notaries[0])
			before := publicStateBytes(t)
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
				t.Fatal("tampered private subscription accepted")
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) || f.fetches != 0 {
				t.Fatal("tampered private data changed state or invoked Git")
			}
		})
	}
}

func TestTeamSubscriptionPreservesPublisherPartyAndStrongerThreshold(t *testing.T) {
	f := newTeamSubscriptionFixture(t, true)
	f.subscribeTeam(t)
	additionalPublisher, _, _ := attest.GenerateKey()
	independent, independentPrivate, _ := attest.GenerateKey()
	if err := attest.PinKey(defaultTrustedKeys(), "additional-publisher", additionalPublisher); err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "independent-reviewer", independent); err != nil {
		t.Fatal(err)
	}
	subscriptions, _ := loadSubscriptions()
	publisherID, independentID := attest.KeyID(additionalPublisher), attest.KeyID(independent)
	subscriptions[0].Parties["publisher"] = append(subscriptions[0].Parties["publisher"], publisherID)
	subscriptions[0].Parties["reviewer"] = []string{independentID}
	subscriptions[0].KeyIDs = append(subscriptions[0].KeyIDs, publisherID, independentID)
	subscriptions[0].Threshold = 3
	if err := saveSubscriptions(subscriptions); err != nil {
		t.Fatal(err)
	}
	before := publicStateBytes(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
		t.Fatal("two parties bypassed a stored threshold of three")
	}
	if !reflect.DeepEqual(before, publicStateBytes(t)) {
		t.Fatal("failed stronger threshold changed pins")
	}
	f.signCatalog(f.publisher, f.notaries[0], independentPrivate)
	f.descriptor.SourceURL, _ = publicsubscription.SourceURL("team", "acme", f.descriptor.CatalogDigest)
	f.signDescriptor(f.notaries[0])
	f.subscribeTeam(t)
	after, _ := loadSubscriptions()
	if after[0].Required() != 3 || !reflect.DeepEqual(after[0].Parties["publisher"], subscriptions[0].Parties["publisher"]) || !reflect.DeepEqual(after[0].Parties["reviewer"], subscriptions[0].Parties["reviewer"]) {
		t.Fatal("descriptor subset weakened the enrolled publisher party or stronger threshold")
	}
	unknown, _, _ := attest.GenerateKey()
	pem, _ := attest.EncodePublicKey(unknown)
	f.descriptor.PublisherKeys = []string{string(pem)}
	f.signDescriptor(f.notaries[0])
	before = publicStateBytes(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
		t.Fatal("unknown publisher joined an existing team subscription")
	}
	if !reflect.DeepEqual(before, publicStateBytes(t)) {
		t.Fatal("unknown publisher was pinned")
	}
}

func TestTeamSubscriptionInstallThenDoctorReportsRealLocalResultAndRevocation(t *testing.T) {
	f := newTeamSubscriptionFixture(t, false)
	f.subscribeTeam(t)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	previous := agents
	agents = []agent{known}
	t.Cleanup(func() { agents = previous })
	client := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", client)
	var frozen string
	stubNativeInstall(t, func(name string) (string, error) { return "/owned/" + name, nil }, func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch strings.Join(args[:3], " ") {
		case "plugin marketplace add":
			frozen = args[len(args)-1]
		case "plugin marketplace list":
			return nativeMarketplaceList(t, "acme", frozen), nil
		case "plugin install --scope":
			copyTree(t, marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0"), filepath.Join(frozen, "plugins", "deploy-runbook"))
		default:
			t.Fatalf("unexpected native request: %s %v", name, args)
		}
		return nil, nil
	})
	capture(t, func() {
		if code := runInstall(nil); code != exitFindings {
			t.Fatalf("first install should offer explicit hook setup: %d", code)
		}
	})
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.LastCheck == nil || !out.LastCheck.Healthy() || out.LastCheck.Checked != 1 || out.ReportAccepted || out.NextAction == nil || out.NextAction.Code != "install_hooks" {
		t.Fatalf("team install lacks an honest local result: %+v", out)
	}
	if _, err := applyClaudeHooks(known.HookConfigPath(), claudeHooks("skillctl")); err != nil {
		t.Fatal(err)
	}
	out, code = doctorResult(t, runDoctor, "--json")
	if code != exitClean || out.Status != "local_checked" || out.ReportAccepted {
		t.Fatalf("identity-only check demanded reporting setup: %+v", out)
	}
	f.denied["/v1/subscriptions/team/acme"] = true
	out, code = doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Status != "needs_attention" || out.ReportAccepted || out.NextAction == nil || out.NextAction.Actor != "team_owner" || !reflect.DeepEqual(out.NextCommand, []string{commandName(), "subscribe", "axela://team/acme"}) || !strings.Contains(out.NextAction.Detail, "membership or machine access") {
		t.Fatalf("revocation was hidden by a previous healthy check: %+v", out)
	}
	if f.fetches != 0 {
		t.Fatal("private lifecycle invoked Git")
	}
}

func TestTeamSubscriptionRedirectsNeverForwardCredentials(t *testing.T) {
	for _, target := range []string{"https://attacker.example/source", "https://axela.app/notary.pub", "https://axela.app/v1/catalogs/another/acme"} {
		t.Run(target, func(t *testing.T) {
			f := newTeamSubscriptionFixture(t, true)
			f.redirectPath, f.redirectTo = "/v1/subscriptions/team/acme", target
			before := publicStateBytes(t)
			if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err == nil {
				t.Fatal("redirect accepted")
			}
			if len(f.authenticated) != 1 || !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("redirect followed or persisted")
			}
		})
	}
}

func TestTeamSubscriptionConcurrentDisconnectRefusesStaleCommit(t *testing.T) {
	f := newTeamSubscriptionFixture(t, true)
	f.subscribeTeam(t)
	f.beforeResponse = func(path string) {
		if publicsubscription.Origin+path == f.descriptor.SourceURL {
			if err := os.Remove(connectStatePath()); err != nil {
				t.Error(err)
			}
			if err := os.Remove(connectCredentialsPath()); err != nil {
				t.Error(err)
			}
		}
	}
	before := publicStateBytes(t)
	_, _, err := f.r.subscribe(context.Background(), "axela://team/acme")
	if err == nil || !strings.Contains(err.Error(), "state changed") {
		t.Fatalf("concurrent disconnect was ignored: %v", err)
	}
	delete(before, "connection.json")
	delete(before, "reporting.token")
	if !reflect.DeepEqual(before, publicStateBytes(t)) {
		t.Fatal("stale subscription overwrote a concurrent disconnect or other saved state")
	}
}

func TestTeamSubscriptionCredentialCannotAuthorizeOtherOriginsOrRoutes(t *testing.T) {
	f := newTeamSubscriptionFixture(t, true)
	access, err := loadSubscriptionAccess("team", "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"https://axela.app/notary.pub", "https://axela.app/v1/keys", "https://github.com/example/acme.git", "https://axela.app.evil/v1/catalogs/team/acme", "https://axela.app/v1/catalogs/other/acme", "https://axela.app/v1/catalogs/team/acme?leak=1"} {
		request, _ := http.NewRequest(http.MethodGet, address, nil)
		if err := access.authorize(request, f.now); err == nil || request.Header.Get("Authorization") != "" || request.Header.Get(publicsubscription.ReadProofHeader) != "" {
			t.Errorf("credential allowed outside bound read: %q", address)
		}
	}
}

func TestTeamSubscriptionBootstrapPreservesAccessBinding(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			f := newTeamSubscriptionFixture(t, true)
			if existing {
				f.subscribeTeam(t)
			}
			notary, _ := attest.EncodePublicKey(f.notaries[0].Public().(ed25519.PublicKey))
			access := "team"
			if existing {
				access = ""
			} // Old servers omit metadata on a repeat bootstrap.
			connection := &enrollment.Connection{Organisation: "team", PublisherKeys: f.descriptor.PublisherKeys, NotaryKeys: []string{string(notary)},
				Catalogs: []enrollment.Catalog{{Name: "acme", Repository: f.descriptor.Repository, Ref: f.descriptor.Ref, URL: f.descriptor.CatalogURL, Access: access}}}
			if notes, err := saveBootstrapSubscriptions(publicsubscription.Origin, connection); err != nil || len(notes) != 0 {
				t.Fatalf("bootstrap: %v %v", notes, err)
			}
			subscriptions, _ := loadSubscriptions()
			if len(subscriptions) != 1 || subscriptions[0].AxelaURI != "axela://team/acme" || subscriptions[0].Access != "team" || subscriptions[0].CatalogName != "acme" {
				t.Fatalf("bootstrap lost team binding: %+v", subscriptions)
			}
			if _, _, err := refreshTeamSubscription(context.Background(), subscriptions[0], f.now); err != nil {
				t.Fatalf("bootstrap binding is not usable for authenticated refresh: %v", err)
			}
			before := publicStateBytes(t)
			connection.Catalogs[0].Access = "team"
			connection.Catalogs[0].URL = publicsubscription.Origin + "/v1/catalogs/other/acme"
			if _, err := saveBootstrapSubscriptions(publicsubscription.Origin, connection); err == nil {
				t.Fatal("bootstrap accepted another team's catalog URL")
			}
			if !reflect.DeepEqual(before, publicStateBytes(t)) {
				t.Fatal("invalid bootstrap changed pins or subscriptions")
			}
			_, code := captureStdout(t, func() int {
				return runSubscribe([]string{f.descriptor.Repository, "--name", "acme", "--key", defaultPublicKey()})
			})
			if code != exitUsage || !reflect.DeepEqual(before, publicStateBytes(t)) || f.fetches != 0 {
				t.Fatal("manual subscribe overwrote a team access binding or invoked Git")
			}
		})
	}
}

func TestTeamSubscriptionLegacyBootstrapNeedsExplicitAccessUpgrade(t *testing.T) {
	f := newTeamSubscriptionFixture(t, true)
	f.subscribeTeam(t)
	subscriptions, _ := loadSubscriptions()
	subscriptions[0].AxelaURI, subscriptions[0].Access = "", ""
	if err := saveSubscriptions(subscriptions); err != nil {
		t.Fatal(err)
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	for _, offline := range []bool{false, true} {
		snapshot, status, err := loadManagedSnapshot(context.Background(), subscriptions[0], trusted, f.now, ManagedCheckOptions{Offline: offline})
		if err == nil || snapshot != nil || status.UsedCached || !strings.Contains(err.Error(), "subscribe axela://team/acme") {
			t.Fatalf("legacy bootstrap used an unauthenticated cache: %+v, %v", status, err)
		}
	}
	f.subscribeTeam(t)
	subscriptions, _ = loadSubscriptions()
	if subscriptions[0].Access != "team" {
		t.Fatal("explicit legacy URI upgrade did not restore the access contract")
	}
}

func TestTeamSubscriptionPreSkillCannotSkipAccessUsingMutableCacheMetadata(t *testing.T) {
	for _, mode := range []string{"source_missing", "source_omits_plugin", "source_and_index_missing", "pins_unreadable", "pins_and_source_unreadable"} {
		t.Run(mode, func(t *testing.T) {
			f := newTeamSubscriptionFixture(t, true)
			f.subscribeTeam(t)
			client := t.TempDir()
			installed := marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0")
			copyTree(t, installed, filepath.Join(f.repository, "plugins", "deploy-runbook"))
			manifestPath := filepath.Join(Home(), "sources", "acme", ".claude-plugin", "marketplace.json")
			if strings.Contains(mode, "source") {
				if err := os.WriteFile(manifestPath, []byte(`{"name":"acme","plugins":[]}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "source_missing" || mode == "source_and_index_missing" {
				if err := os.Remove(manifestPath); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "source_and_index_missing" {
				subscriptions, _ := loadSubscriptions()
				if err := os.Remove(indexPath(subscriptions[0])); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(mode, "pins") {
				if err := os.WriteFile(defaultTrustedKeys(), []byte("unreadable pin store"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.offline = true
			before, _ := os.ReadFile(filepath.Join(installed, "SKILL.md"))
			for _, permissive := range []bool{false, true} {
				args := []string{"--claude-home", client}
				if permissive {
					args = append(args, "--permissive")
				}
				var output, diagnostic bytes.Buffer
				code := runHookPreSkillTo(args, strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"deploy-runbook:run"}}`), &output, &diagnostic)
				if code != exitDeny || diagnostic.Len() == 0 {
					t.Fatalf("private invocation bypassed current access: code=%d diagnostic=%q", code, diagnostic.String())
				}
			}
			after, _ := os.ReadFile(filepath.Join(installed, "SKILL.md"))
			if !bytes.Equal(before, after) {
				t.Fatal("a failed private pre-skill check changed installed bytes")
			}
		})
	}
}
