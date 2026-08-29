package notary

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/catalog"
	"time"
)

type issuer struct {
	key    *rsa.PrivateKey
	keyID  string
	server *httptest.Server
}

func newIssuer(t *testing.T) *issuer { return newIssuerNamed(t, "test-key") }

// newIssuerNamed is the same fixture with its own key id, which is what a second issuer
// needs: two fixtures sharing one kid cannot show a key being withdrawn or kept.
func newIssuerNamed(t *testing.T, keyID string) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": keyID,
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	}))
	t.Cleanup(server.Close)
	return &issuer{key: key, keyID: keyID, server: server}
}

type tokenSpec struct {
	algorithm  string
	issuer     string
	audience   any
	repository string
	ref        string
	expiry     time.Time
}

func (i *issuer) mint(t *testing.T, spec tokenSpec) string {
	t.Helper()
	if spec.algorithm == "" {
		spec.algorithm = "RS256"
	}
	if spec.issuer == "" {
		spec.issuer = GitHubIssuer
	}
	if spec.audience == nil {
		spec.audience = DefaultAudience
	}
	if spec.expiry.IsZero() {
		spec.expiry = time.Now().Add(5 * time.Minute)
	}

	header, _ := json.Marshal(map[string]string{"alg": spec.algorithm, "kid": "test-key"})
	claims, _ := json.Marshal(map[string]any{
		"iss": spec.issuer, "aud": spec.audience,
		"exp": spec.expiry.Unix(), "repository": spec.repository, "ref": spec.ref,
	})
	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func withOIDC(f *fixture, i *issuer, repositories ...string) *fixture {
	org := f.orgs["acme"]
	org.GitHubRepositories = repositories
	f.orgs["acme"] = org
	f.service.WithOIDC(&OIDCVerifier{JWKSURL: i.server.URL})
	return f
}

// The point of the whole feature: a workflow of the registered repository publishes with
// the token GitHub minted for it, no static secret anywhere — and the catalog it submits
// still has to be signed by the pinned publisher key.
func TestARegisteredRepositorysTokenPublishes(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace")

	token := i.mint(t, tokenSpec{repository: "acme/marketplace"})
	if response := f.publish(t, token, f.signedCatalog(t, 1)); response.StatusCode != http.StatusOK {
		t.Fatalf("an OIDC publish answered %s", response.Status)
	}
	if _, err := f.service.Serve("acme", "plugins"); err != nil {
		t.Fatalf("the catalog must have been stored: %v", err)
	}
}

func TestTokensThatMustNotPublish(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace")

	cases := map[string]string{
		"another repository": i.mint(t, tokenSpec{repository: "attacker/fork"}),
		"no repository":      i.mint(t, tokenSpec{}),
		"expired":            i.mint(t, tokenSpec{repository: "acme/marketplace", expiry: time.Now().Add(-time.Hour)}),
		"wrong audience":     i.mint(t, tokenSpec{repository: "acme/marketplace", audience: "someone-else"}),
		"wrong issuer":       i.mint(t, tokenSpec{repository: "acme/marketplace", issuer: "https://evil.example.com"}),
		"alg none": strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"test-key"}`)),
			base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + GitHubIssuer + `","aud":"` + DefaultAudience + `","repository":"acme/marketplace","exp":9999999999}`)),
			"",
		}, "."),
	}
	for name, token := range cases {
		if response := f.publish(t, token, f.signedCatalog(t, 1)); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s answered %s, not 401", name, response.Status)
		}
	}
}

// A valid OIDC token authenticates the pipeline; it does not replace the publisher's
// signature. The same boundary as everywhere else: the credential opens the door, the
// signature decides what may come through it.
func TestOIDCDoesNotBypassThePublisherSignature(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace")

	token := i.mint(t, tokenSpec{repository: "acme/marketplace"})
	if response := f.publish(t, token, []byte(`{"payloadType":"x","payload":"e30=","signatures":[]}`)); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("an unsigned catalog with a valid token answered %s, not 422", response.Status)
	}
}

func TestTheStaticTokenStillWorksBesideOIDC(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace")

	if response := f.publish(t, "publish-token", f.signedCatalog(t, 1)); response.StatusCode != http.StatusOK {
		t.Fatalf("the static token answered %s", response.Status)
	}
}

// An organisation that registered no repository must not accept any JWT, however valid:
// OIDC is opt-in per organisation, not a door that ships open.
func TestOIDCIsClosedForUnregisteredOrgs(t *testing.T) {
	i := newIssuer(t)
	f := newFixture(t)
	f.service.WithOIDC(&OIDCVerifier{JWKSURL: i.server.URL})

	token := i.mint(t, tokenSpec{repository: "acme/marketplace"})
	if response := f.publish(t, token, f.signedCatalog(t, 1)); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a JWT against an unregistered org answered %s, not 401", response.Status)
	}
}

// Registering "owner/repo@ref" binds the branch. Without the binding, a workflow on any
// branch of the repository may submit; with it, a topic branch's token is refused even
// though the repository matches. Plain "owner/repo" keeps accepting any ref, because
// every organisation registered before refs existed wrote it that way.
func TestARegisteredRefIsBinding(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace@refs/heads/main")

	main := i.mint(t, tokenSpec{repository: "acme/marketplace", ref: "refs/heads/main"})
	if response := f.publish(t, main, f.signedCatalog(t, 1)); response.StatusCode != http.StatusOK {
		t.Fatalf("the registered ref answered %s", response.Status)
	}

	branch := i.mint(t, tokenSpec{repository: "acme/marketplace", ref: "refs/heads/topic"})
	if response := f.publish(t, branch, f.signedCatalog(t, 2)); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a topic branch against a ref-bound registration answered %s, not 401", response.Status)
	}

	missing := i.mint(t, tokenSpec{repository: "acme/marketplace"})
	if response := f.publish(t, missing, f.signedCatalog(t, 2)); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a token with no ref against a ref-bound registration answered %s, not 401", response.Status)
	}
}

func TestAPlainRegistrationAcceptsAnyRef(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace")

	branch := i.mint(t, tokenSpec{repository: "acme/marketplace", ref: "refs/heads/anything"})
	if response := f.publish(t, branch, f.signedCatalog(t, 1)); response.StatusCode != http.StatusOK {
		t.Fatalf("an unbound registration refused a branch: %s", response.Status)
	}
}

// An organisation publishes more than one catalog, and those catalogs live in different
// repositories. Every registered one publishes; the ref binding stays attached to the
// registration that carries it rather than leaking onto its neighbours.
func TestEveryRegisteredRepositoryPublishes(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace", "acme/curated@refs/heads/main")

	for name, spec := range map[string]tokenSpec{
		"the first registration":       {repository: "acme/marketplace", ref: "refs/heads/topic"},
		"the second, on its bound ref": {repository: "acme/curated", ref: "refs/heads/main"},
	} {
		if _, _, err := f.service.AuthorizeOIDC("acme", i.mint(t, spec), time.Now()); err != nil {
			t.Errorf("%s must publish: %v", name, err)
		}
	}

	_, _, err := f.service.AuthorizeOIDC("acme",
		i.mint(t, tokenSpec{repository: "acme/curated", ref: "refs/heads/topic"}), time.Now())
	if err == nil {
		t.Fatal("a ref-bound registration must refuse another branch")
	}
	// The message decides where the operator looks next: they are who they said they are
	// and got the branch wrong, so naming the repository unregistered sends them to fix
	// a registration that is already correct.
	if !strings.Contains(err.Error(), "refs/heads/main") {
		t.Errorf("the refusal must name the branch that publishes, got: %v", err)
	}
}

// refusingGate records what it saw and refuses.
type refusingGate struct {
	seen   Provenance
	skills int
	err    error
}

func (g *refusingGate) Admit(_ context.Context, snapshot *catalog.Snapshot, where Provenance) error {
	g.seen, g.skills = where, len(snapshot.Skills)
	return g.err
}

// A gate that refuses must stop the publication, and it must do so before the notary
// countersigns: a signature exists once it is made, and one made for a catalog the
// deployment then rejected is a signature on record for something nobody approved.
func TestARefusingGateStopsThePublishBeforeAnythingIsSigned(t *testing.T) {
	i := newIssuer(t)
	gate := &refusingGate{err: fmt.Errorf("%w: the scan found something", ErrRefused)}
	f := withOIDC(newFixture(t), i, "acme/marketplace")
	f.service.WithGate(gate)

	token := i.mint(t, tokenSpec{repository: "acme/marketplace"})
	if response := f.publish(t, token, f.signedCatalog(t, 1)); response.StatusCode == http.StatusOK {
		t.Fatal("a refused publish must not answer OK")
	}
	if _, err := f.service.Serve("acme", "plugins"); err == nil {
		t.Error("a refused catalog must not have been stored")
	}

	// The gate must be told where the bytes are, from claims GitHub minted rather than
	// anything the caller sent — otherwise it checks whatever the publisher preferred.
	if gate.seen.Repository != "acme/marketplace" {
		t.Errorf("the gate was not told the repository, got %q", gate.seen.Repository)
	}
	if gate.seen.Organisation != "acme" || gate.seen.Marketplace != "plugins" {
		t.Errorf("the gate was not told what it is admitting: %+v", gate.seen)
	}
}

// The seam must be invisible when nothing installs it: a self-hoster running the binary
// gets the behaviour they had before, with no network call and nothing to configure.
func TestNoGateMeansNoChange(t *testing.T) {
	i := newIssuer(t)
	f := withOIDC(newFixture(t), i, "acme/marketplace")
	token := i.mint(t, tokenSpec{repository: "acme/marketplace"})
	if response := f.publish(t, token, f.signedCatalog(t, 1)); response.StatusCode != http.StatusOK {
		t.Fatalf("a publish with no gate installed answered %s", response.Status)
	}
}

// The cache merges rather than replaces. A JWKS answer that transiently omits a key — a
// partial response, one server mid-rotation, a degraded CDN — used to evict a key that was
// working, and every token signed with it was then rejected as unknown.
func TestAPartialJWKSAnswerDoesNotWithdrawAWorkingKey(t *testing.T) {
	i := newIssuer(t)
	verifier := &OIDCVerifier{JWKSURL: i.server.URL}
	now := time.Now()

	key, err := verifier.keyFor(i.keyID, now)
	if err != nil || key == nil {
		t.Fatalf("the issuer's key must be learned: %v", err)
	}

	// The issuer now answers with a different key and no longer mentions the first.
	other := newIssuerNamed(t, "second-key")
	verifier.JWKSURL = other.server.URL
	if _, err := verifier.keyFor(other.keyID, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("the new key must be learned: %v", err)
	}
	if _, ok := verifier.cached(i.keyID, now.Add(2*time.Minute)); !ok {
		t.Error("a key missing from one answer was withdrawn; tokens signed with it now fail")
	}
}

// Merging forever would mean a key the issuer deliberately withdrew stays trusted for as
// long as the process lives. The age bound is what makes merging safe.
func TestAKeyThatStopsBeingPublishedEventuallyExpires(t *testing.T) {
	i := newIssuer(t)
	verifier := &OIDCVerifier{JWKSURL: i.server.URL}
	now := time.Now()
	if _, err := verifier.keyFor(i.keyID, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := verifier.cached(i.keyID, now.Add(MaxKeyAge-time.Minute)); !ok {
		t.Error("a key must stay usable inside its age; a shorter life would reject good tokens")
	}
	if _, ok := verifier.cached(i.keyID, now.Add(MaxKeyAge+time.Minute)); ok {
		t.Error("a key unseen past MaxKeyAge must stop being accepted")
	}
}

// The fetch must not run under the lock. Holding it across a ten-second HTTP call queued
// every concurrent verification behind one slow issuer, which behind a gateway that cuts
// connections at thirty seconds turns a slow JWKS endpoint into an outage.
func TestVerificationDoesNotQueueBehindOneSlowFetch(t *testing.T) {
	slow := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-slow
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	defer close(slow)

	verifier := &OIDCVerifier{JWKSURL: server.URL}
	verifier.mu.Lock()
	verifier.keys = map[string]cachedKey{"known": {key: &rsa.PublicKey{}, seen: time.Now()}}
	verifier.mu.Unlock()

	started := make(chan struct{})
	go func() {
		close(started)
		verifier.keyFor("unknown", time.Now()) // blocks in the slow fetch
	}()
	<-started
	time.Sleep(150 * time.Millisecond) // let it reach the fetch

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := verifier.keyFor("known", time.Now()); err != nil {
			t.Errorf("a cached key must answer while another fetch is in flight: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a cached lookup blocked behind an in-flight JWKS fetch")
	}
}

// An issuer that answers with nothing usable is a failure, not a successful refresh with
// zero keys — those look identical to the caller and only one of them is worth retrying.
func TestAnEmptyJWKSIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	if _, err := (&OIDCVerifier{JWKSURL: server.URL}).fetch(); err == nil {
		t.Error("an issuer publishing no usable key must be an error")
	}
}
