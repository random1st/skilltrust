package notary

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

// rotatingFixture is a notary mid-rotation: two countersigning keys, old one primary.
type rotatingFixture struct {
	*fixture
	oldPub ed25519.PublicKey
	newPub ed25519.PublicKey
}

func newRotatingFixture(t *testing.T) *rotatingFixture {
	t.Helper()
	f := newFixture(t)
	f.server.Close()

	oldPub, oldKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.service = NewFrom(NewFileStorage(t.TempDir()), f.orgs, oldKey, newKey)
	f.server = httptest.NewServer(f.service.Handler())
	t.Cleanup(f.server.Close)
	return &rotatingFixture{fixture: f, oldPub: oldPub, newPub: newPub}
}

// The overlap window's whole purpose: a catalog countersigned mid-rotation verifies at
// threshold 2 for a machine that pinned the outgoing key AND for one that pinned the
// incoming key. Neither fleet breaks while pins catch up.
func TestRotationCountersignsWithEveryCurrentKey(t *testing.T) {
	f := newRotatingFixture(t)

	response := f.publish(t, "publish-token", f.signedCatalog(t, 1))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("publish answered %s", response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}

	for name, notaryPub := range map[string]ed25519.PublicKey{
		"outgoing": f.oldPub,
		"incoming": f.newPub,
	} {
		pinned := attest.NewTrustedKeys(f.publisherPub, notaryPub)
		_, signers, err := attest.VerifyPayloadSigners(&envelope, catalog.PayloadType, pinned)
		if err != nil {
			t.Fatalf("machine pinning the %s key: %v", name, err)
		}
		if len(signers) != 2 {
			t.Fatalf("machine pinning the %s key sees %d signers, needs 2 for its threshold",
				name, len(signers))
		}
	}
}

// /v1/keys is the read side of rotation: signed by every current key, verifiable by a
// machine that pins either one, opaque to a stranger who pins neither.
func TestKeySetEndpointExtendsTrustFromEitherKey(t *testing.T) {
	f := newRotatingFixture(t)

	response, err := http.Get(f.server.URL + "/v1/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/v1/keys answered %s", response.Status)
	}
	var envelope attest.Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}

	for name, pinned := range map[string]ed25519.PublicKey{
		"outgoing": f.oldPub,
		"incoming": f.newPub,
	} {
		set, _, err := attest.VerifyKeySet(&envelope, attest.NewTrustedKeys(pinned))
		if err != nil {
			t.Fatalf("pinning the %s key must verify the announcement: %v", name, err)
		}
		if len(set.Keys) != 2 {
			t.Fatalf("the announcement must name both keys, got %d", len(set.Keys))
		}
	}

	strangerPub, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := attest.VerifyKeySet(&envelope, attest.NewTrustedKeys(strangerPub)); !errors.Is(err, attest.ErrUntrustedKey) {
		t.Fatalf("a machine pinning neither key must refuse the announcement, got %v", err)
	}
}

// /notary.pub keeps serving exactly the primary key through a rotation, because it is
// what the printed subscribe instructions fetch and those instructions predate the
// incoming key.
func TestNotaryPubServesThePrimaryKey(t *testing.T) {
	f := newRotatingFixture(t)

	response, err := http.Get(f.server.URL + "/notary.pub")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	pem, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	served, err := attest.ParsePublicKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	if attest.KeyID(served) != attest.KeyID(f.oldPub) {
		t.Fatal("/notary.pub must serve the primary (outgoing) key during rotation")
	}
	if got := response.Header.Get("X-Key-Id"); got != attest.KeyID(f.oldPub) {
		t.Fatalf("X-Key-Id names %s, not the primary key", got)
	}
}

// The announcement is fresh on every request rather than cached: its issued_at moves.
// Pinning that here is cheap insurance that a rotated key set is served immediately
// after a deploy, not after some cache expires.
func TestKeySetIsSignedAtRequestTime(t *testing.T) {
	f := newRotatingFixture(t)

	fetch := func() time.Time {
		t.Helper()
		response, err := http.Get(f.server.URL + "/v1/keys")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var envelope attest.Envelope
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		set, _, err := attest.VerifyKeySet(&envelope, attest.NewTrustedKeys(f.oldPub))
		if err != nil {
			t.Fatal(err)
		}
		return set.IssuedAt
	}

	first := fetch()
	time.Sleep(5 * time.Millisecond)
	if second := fetch(); !second.After(first) {
		t.Fatal("two requests returned the same issued_at; the announcement looks cached")
	}
}
