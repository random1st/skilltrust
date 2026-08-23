package source

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func destination(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "indexes", "acme.dsse.json")
}

func TestFetchIndexStoresWhatTheServerSent(t *testing.T) {
	body := `{"payload":"e30=","signatures":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()

	target := destination(t)
	if err := FetchIndex(server.URL, target); err != nil {
		t.Fatalf("FetchIndex: %v", err)
	}
	stored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("the index was not written: %v", err)
	}
	if string(stored) != body {
		t.Fatalf("stored %q, served %q", stored, body)
	}
}

func TestFetchIndexRefusesPlainHTTPOffThisMachine(t *testing.T) {
	err := FetchIndex("http://notary.example.com/catalog", destination(t))
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("plain HTTP to a remote host must be refused, got %v", err)
	}
}

func TestFetchIndexRefusesAnErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	if err := FetchIndex(server.URL, destination(t)); err == nil {
		t.Fatal("a 404 must not become an empty index")
	}
}

// A redirect is the server changing the URL the machine decided to trust; following it
// silently would let a compromised notary bounce the fetch anywhere, including to HTTP.
func TestFetchIndexDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
	}))
	defer server.Close()

	if err := FetchIndex(server.URL, destination(t)); err == nil {
		t.Fatal("a redirect must surface as an error, not be followed")
	}
}

func TestFetchIndexRefusesNonJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>sign in to continue</html>"))
	}))
	defer server.Close()

	target := destination(t)
	if err := FetchIndex(server.URL, target); err == nil {
		t.Fatal("a captive portal's HTML must not be stored as an index")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("a refused response must leave nothing at the destination")
	}
}

func TestFetchIndexRefusesAnOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"padding":"`))
		padding := make([]byte, MaxIndexBytes)
		for i := range padding {
			padding[i] = 'a'
		}
		w.Write(padding)
		w.Write([]byte(`"}`))
	}))
	defer server.Close()

	if err := FetchIndex(server.URL, destination(t)); err == nil {
		t.Fatal("an index above the size limit must be refused")
	}
}

// A failed fetch must not clobber the index a previous successful fetch stored: the
// session hook reads that file offline, and "the notary was briefly down" must degrade to
// staleness the freshness check already handles, not to a missing catalog.
func TestFetchIndexKeepsThePreviousIndexOnFailure(t *testing.T) {
	target := destination(t)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := `{"payload":"previous"}`
	if err := os.WriteFile(target, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer server.Close()

	if err := FetchIndex(server.URL, target); err == nil {
		t.Fatal("a 500 must be an error")
	}
	stored, err := os.ReadFile(target)
	if err != nil || string(stored) != previous {
		t.Fatalf("the previous index must survive a failed fetch; got %q, %v", stored, err)
	}
}
