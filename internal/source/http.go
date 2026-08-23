package source

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// MaxIndexBytes bounds a fetched index. A signed catalog names plugins and digests; one
// that does not fit in this is not a catalog, and reading an unbounded response hands the
// server a lever over this machine's memory.
const MaxIndexBytes = 8 << 20

// indexClient does not follow a redirect. The URL a machine subscribed to is part of what
// it decided to trust, and a redirect is the server quietly changing that decision — to a
// host the operator never saw, possibly downgraded to plain HTTP.
var indexClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// FetchIndex downloads a signed catalog envelope over HTTPS and stores it at destination.
//
// It deliberately does not verify anything about the contents beyond being JSON: the
// signature check belongs to the one verification path every catalog goes through,
// regardless of how it arrived. What this function owns is the transport — TLS, size,
// and writing atomically so a failure mid-download cannot leave half an index where the
// verifier will look.
func FetchIndex(address, destination string) error {
	parsed, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("catalog URL %q is not a URL: %w", address, err)
	}
	if parsed.Scheme != "https" && !loopback(parsed.Hostname()) {
		return fmt.Errorf("catalog URL %q is not https; a signed index fetched in the "+
			"clear invites the substitution the signature exists to catch", address)
	}

	response, err := indexClient.Get(address)
	if err != nil {
		return fmt.Errorf("cannot fetch the catalog index: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the catalog index at %s answered %s", address, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxIndexBytes+1))
	if err != nil {
		return fmt.Errorf("cannot read the catalog index: %w", err)
	}
	if len(body) > MaxIndexBytes {
		return fmt.Errorf("the catalog index at %s is larger than %d bytes; refusing it",
			address, MaxIndexBytes)
	}
	if !json.Valid(body) {
		return fmt.Errorf("the catalog index at %s is not JSON; not keeping it", address)
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".index-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), destination)
}

// loopback allows plain HTTP only to this machine itself, which is what tests and a local
// notary during development use. Anything reachable over a network keeps the TLS
// requirement.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if address := net.ParseIP(host); address != nil {
		return address.IsLoopback()
	}
	return false
}
