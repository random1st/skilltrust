package notary

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type issuer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	}))
	t.Cleanup(server.Close)
	return &issuer{key: key, server: server}
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

func withOIDC(f *fixture, i *issuer, repository string) *fixture {
	org := f.orgs["acme"]
	org.GitHubRepository = repository
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
