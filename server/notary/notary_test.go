package notary

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

type fixture struct {
	service      *Service
	orgs         StaticDirectory
	server       *httptest.Server
	publisher    ed25519.PrivateKey
	publisherPub ed25519.PublicKey
	notaryPub    ed25519.PublicKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	publisherPub, publisherKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	notaryPub, notaryKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	orgs := StaticDirectory{"acme": {
		Name:       "acme",
		Token:      NewSecret("publish-token"),
		Publishers: attest.NewTrustedKeys(publisherPub),
	}}
	service := NewFrom(NewFileStorage(t.TempDir()), orgs, notaryKey)
	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)
	return &fixture{
		service: service, orgs: orgs, server: server,
		publisher: publisherKey, publisherPub: publisherPub, notaryPub: notaryPub,
	}
}

func (f *fixture) signedCatalog(t *testing.T, sequence int64) []byte {
	t.Helper()
	now := time.Now().UTC()
	envelope, err := catalog.Sign(catalog.Snapshot{
		Name: "plugins", Sequence: sequence,
		IssuedAt: now, ValidUntil: now.Add(7 * 24 * time.Hour),
		Skills: []catalog.Managed{{Name: "deploy-runbook", Digest: "sha256:aa", Version: "1.0.0"}},
	}, f.publisher)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (f *fixture) publish(t *testing.T, token string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/catalogs/acme/plugins", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

// The whole point, end to end: a publisher's catalog goes in with one signature, comes
// out with two, and a machine that pinned both keys sees both signers — which is what
// lets a subscription demand threshold 2.
func TestPublishCountersignsAndServes(t *testing.T) {
	f := newFixture(t)

	response := f.publish(t, "publish-token", f.signedCatalog(t, 1))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("publish answered %s", response.Status)
	}

	fetched, err := http.Get(f.server.URL + "/v1/catalogs/acme/plugins")
	if err != nil {
		t.Fatal(err)
	}
	defer fetched.Body.Close()
	body, err := io.ReadAll(fetched.Body)
	if err != nil {
		t.Fatal(err)
	}

	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("the served catalog is not an envelope: %v", err)
	}
	trusted := attest.NewTrustedKeys(f.publisherPub, f.notaryPub)
	_, signers, err := catalog.VerifySigners(&envelope, trusted, nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("a machine pinning both keys must accept the served catalog: %v", err)
	}
	if len(signers) != 2 {
		t.Fatalf("signers = %v; the publisher and the notary must both count", signers)
	}
}

// A CI job that gets re-run submits the countersigned output of its previous run. That
// must be idempotent — same catalog out, two signatures, not three and not a refusal.
// The same code path also stops an uploader planting a garbage signature under the
// notary's key id, which would otherwise make every threshold-2 machine refuse the
// envelope as a forgery.
func TestRepublishingTheCountersignedOutputIsIdempotent(t *testing.T) {
	f := newFixture(t)

	first := f.publish(t, "publish-token", f.signedCatalog(t, 1))
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first publish: %s", first.Status)
	}
	countersigned, err := io.ReadAll(first.Body)
	if err != nil {
		t.Fatal(err)
	}

	second := f.publish(t, "publish-token", countersigned)
	if second.StatusCode != http.StatusOK {
		t.Fatalf("republishing the countersigned catalog answered %s", second.Status)
	}
	body, err := io.ReadAll(second.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Signatures) != 2 {
		t.Fatalf("%d signatures after a re-run; it must stay publisher + notary", len(envelope.Signatures))
	}
	trusted := attest.NewTrustedKeys(f.publisherPub, f.notaryPub)
	if _, signers, err := catalog.VerifySigners(&envelope, trusted, nil, time.Now().UTC()); err != nil || len(signers) != 2 {
		t.Fatalf("the re-run output must still verify with both signers: %v, %v", signers, err)
	}
}

func TestAWrongTokenPublishesNothing(t *testing.T) {
	f := newFixture(t)

	for _, token := range []string{"", "wrong"} {
		if response := f.publish(t, token, f.signedCatalog(t, 1)); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q answered %s, not 401", token, response.Status)
		}
	}
	if _, err := f.service.Serve("acme", "plugins"); err == nil {
		t.Fatal("a refused publish must leave nothing to serve")
	}
}

// The notary must not put its signature on a catalog its own registry did not sign;
// otherwise "countersigned" would mean "uploaded by anyone with a token".
func TestACatalogFromAStrangerIsRefused(t *testing.T) {
	f := newFixture(t)
	_, strangerKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope, err := catalog.Sign(catalog.Snapshot{
		Name: "plugins", Sequence: 1, IssuedAt: now, ValidUntil: now.Add(time.Hour),
	}, strangerKey)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(envelope)

	if response := f.publish(t, "publish-token", body); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a stranger's catalog answered %s, not 422", response.Status)
	}
}

func TestGarbageIsRefused(t *testing.T) {
	f := newFixture(t)
	if response := f.publish(t, "publish-token", []byte("not a catalog")); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("garbage answered %s, not 422", response.Status)
	}
}

// Replaying an old catalog is how a revocation gets undone. The notary refuses it even
// from a caller holding a valid token, because the token authenticates the pipeline, and
// a compromised pipeline is exactly the case rollback protection is for.
func TestAnOlderSequenceIsRefusedAndThePublishedOneStays(t *testing.T) {
	f := newFixture(t)

	if response := f.publish(t, "publish-token", f.signedCatalog(t, 5)); response.StatusCode != http.StatusOK {
		t.Fatalf("sequence 5: %s", response.Status)
	}
	if response := f.publish(t, "publish-token", f.signedCatalog(t, 4)); response.StatusCode != http.StatusConflict {
		t.Fatalf("sequence 4 after 5 answered %s, not 409", response.Status)
	}

	body, err := f.service.Serve("acme", "plugins")
	if err != nil {
		t.Fatal(err)
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := catalog.Open(&envelope, attest.NewTrustedKeys(f.publisherPub))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Sequence != 5 {
		t.Fatalf("served sequence %d; the replay must not have replaced it", snapshot.Sequence)
	}
}

func TestAnExpiredCatalogIsNotCountersigned(t *testing.T) {
	f := newFixture(t)
	stale := time.Now().UTC().Add(-48 * time.Hour)
	envelope, err := catalog.Sign(catalog.Snapshot{
		Name: "plugins", Sequence: 1, IssuedAt: stale, ValidUntil: stale.Add(time.Hour),
	}, f.publisher)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(envelope)

	if response := f.publish(t, "publish-token", body); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("an expired catalog answered %s, not 422", response.Status)
	}
}

func TestFetchingTheUnpublishedIsNotFound(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{
		"/v1/catalogs/acme/plugins",   // valid names, nothing published
		"/v1/catalogs/acme/..",        // traversal shaped like a name
		"/v1/catalogs/nobody/plugins", // unknown organisation
	} {
		response, err := http.Get(f.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s answered %s, not 404", path, response.Status)
		}
	}
}

// The subscribe instructions every consumer sees end "--key notary.pub --threshold 2".
// This pins that the file those instructions name is actually served, that it parses as
// a key, and that it is the countersigning key rather than some other one.
func TestNotaryKeyIsServedAsInstructed(t *testing.T) {
	f := newFixture(t)
	response, err := http.Get(f.server.URL + "/notary.pub")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /notary.pub answered %s", response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	served, err := attest.ParsePublicKey(body)
	if err != nil {
		t.Fatalf("what was served does not parse as a public key: %v", err)
	}
	if !served.Equal(f.notaryPub) {
		t.Fatal("the key served is not the countersigning key")
	}
	if got := response.Header.Get("X-Key-Id"); got != f.service.KeyID() {
		t.Fatalf("X-Key-Id says %q, the service says %q", got, f.service.KeyID())
	}
}
