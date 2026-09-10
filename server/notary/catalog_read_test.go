package notary

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

// rememberingStorage is file storage that also keeps provenance, which is what a hosted
// deployment has and the self-hosted file storage deliberately does not. The rule under
// test only engages where provenance exists, so testing it needs a storage that keeps it.
type rememberingStorage struct {
	Storage
	provenance map[string]Provenance
}

func (r *rememberingStorage) PutCatalogProvenance(org, marketplace string, where Provenance, digest string) error {
	r.provenance[org+"/"+marketplace+"/"+digest] = where
	return nil
}

func (r *rememberingStorage) GetCatalogProvenance(org, marketplace, digest string) (Provenance, error) {
	where, ok := r.provenance[org+"/"+marketplace+"/"+digest]
	if !ok {
		return Provenance{}, ErrAbsent
	}
	return where, nil
}

// remembering swaps the fixture's storage for one that keeps provenance, before anything
// is published through it.
func remembering(t *testing.T, f *fixture) *fixture {
	t.Helper()
	f.service.storage = &rememberingStorage{Storage: f.service.storage, provenance: map[string]Provenance{}}
	return f
}

// fetchCatalog reads a catalog the way a consumer does, optionally with a credential.
func fetchCatalog(t *testing.T, f *fixture, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/v1/catalogs/acme/plugins", nil)
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

// recordVisibility files provenance for whatever is currently published, the way an OIDC
// publish does — keyed by the digest of the exact countersigned bytes readers get.
func recordVisibility(t *testing.T, f *fixture, visibility string) {
	t.Helper()
	body, err := f.service.Serve("acme", "plugins")
	if err != nil {
		t.Fatal(err)
	}
	storage, ok := f.service.storage.(CatalogProvenanceStorage)
	if !ok {
		t.Skip("this storage keeps no provenance")
	}
	sum := sha256.Sum256(body)
	where := Provenance{
		Organisation: "acme", Marketplace: "plugins",
		Repository: "acme/plugins", Ref: "refs/heads/main",
		Commit: "0123456789abcdef0123456789abcdef01234567", RepositoryVisibility: visibility,
	}
	if err := storage.PutCatalogProvenance("acme", "plugins", where, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
}

// A catalog from a private repository is not a stranger's to read.
//
// It was, until now. Names, versions and the canonical digest of every skill in a private
// repository were served to anybody who guessed the path, and a digest is a cheap oracle:
// it confirms a guess about bytes nobody outside was meant to hold.
func TestAPrivateRepositorysCatalogIsNotServedToStrangers(t *testing.T) {
	f := remembering(t, newFixture(t))
	f.publish(t, "publish-token", f.signedCatalog(t, 1))
	recordVisibility(t, f, "private")

	response := fetchCatalog(t, f, "")
	// Absent, not forbidden: 401 would confirm that this organisation publishes at all,
	// and the names here are the company's and its repository's.
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("a private catalog answered %d to a stranger, want 404", response.StatusCode)
	}

	if response := fetchCatalog(t, f, "publish-token"); response.StatusCode != http.StatusOK {
		t.Fatalf("the organisation's own token answered %d, want 200", response.StatusCode)
	}
	if response := fetchCatalog(t, f, "not-the-token"); response.StatusCode != http.StatusNotFound {
		t.Fatalf("a wrong token answered %d, want 404", response.StatusCode)
	}
}

// The point of a catalog is that machines can read it. Every consumer following a public
// one today does so with no credential at all, and closing that would be a far larger
// outage than the leak this fixes.
func TestAPublicRepositorysCatalogStaysOpen(t *testing.T) {
	f := remembering(t, newFixture(t))
	f.publish(t, "publish-token", f.signedCatalog(t, 1))
	recordVisibility(t, f, "public")

	if response := fetchCatalog(t, f, ""); response.StatusCode != http.StatusOK {
		t.Fatalf("a public catalog answered %d without a credential, want 200", response.StatusCode)
	}
}

// Provenance that says nothing is not evidence of anything, and is served as it always
// was. A static-token publish records none, and neither did anything published before the
// visibility field existed — a self-hosted notary serving its own machines is exactly that
// case, and refusing it would break a working deployment to protect it from a leak it may
// not have.
func TestACatalogWithNoProvenanceIsServedAsBefore(t *testing.T) {
	f := newFixture(t)
	f.publish(t, "publish-token", f.signedCatalog(t, 1))

	if response := fetchCatalog(t, f, ""); response.StatusCode != http.StatusOK {
		t.Fatalf("a catalog with no recorded provenance answered %d, want 200", response.StatusCode)
	}
}

// Provenance is keyed by the digest of the exact bytes served, so republishing must not
// leave a private catalog readable through a stale record of an older envelope.
func TestRepublishingDoesNotCarryTheOldVisibilityForward(t *testing.T) {
	f := remembering(t, newFixture(t))
	f.publish(t, "publish-token", f.signedCatalog(t, 1))
	recordVisibility(t, f, "public")
	if response := fetchCatalog(t, f, ""); response.StatusCode != http.StatusOK {
		t.Fatal("the public catalog was not readable to begin with")
	}

	f.publish(t, "publish-token", f.signedCatalog(t, 2))
	recordVisibility(t, f, "private")
	if response := fetchCatalog(t, f, ""); response.StatusCode != http.StatusNotFound {
		t.Fatalf("after republishing as private the catalog answered %d, want 404", response.StatusCode)
	}
}
