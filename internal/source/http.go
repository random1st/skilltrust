package source

import (
	"context"
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

// FetchJSON downloads a JSON document over HTTPS under the same transport rules as an
// index — TLS or loopback, bounded size, no redirects — and returns the bytes. It is the
// transport for documents that are verified in memory rather than stored, such as a
// notary's signed key-set announcement.
func FetchJSON(address string) ([]byte, error) {
	return FetchJSONContext(context.Background(), address)
}

// FetchJSONContext is FetchJSON with a caller-provided context.
func FetchJSONContext(ctx context.Context, address string) ([]byte, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL: %w", address, err)
	}
	if parsed.Scheme != "https" && !Loopback(parsed.Hostname()) {
		return nil, fmt.Errorf("%q is not https; a signed document fetched in the "+
			"clear invites the substitution the signature exists to catch", address)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	response, err := indexClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch %s: %w", address, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", address, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxIndexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", address, err)
	}
	if len(body) > MaxIndexBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes; refusing it", address, MaxIndexBytes)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("%s is not JSON", address)
	}
	return body, nil
}

// FetchIndex downloads a signed catalog envelope over HTTPS and stores it at destination.
//
// It deliberately does not verify anything about the contents beyond being JSON: the
// signature check belongs to the one verification path every catalog goes through,
// regardless of how it arrived. What this function owns is the transport — TLS, size,
// and writing atomically so a failure mid-download cannot leave half an index where the
// verifier will look.
func FetchIndex(address, destination string) error {
	return FetchIndexContext(context.Background(), address, destination)
}

// FetchIndexContext is FetchIndex with a caller-provided context.
func FetchIndexContext(ctx context.Context, address, destination string) error {
	parsed, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("catalog URL %q is not a URL: %w", address, err)
	}
	if parsed.Scheme != "https" && !Loopback(parsed.Hostname()) {
		return fmt.Errorf("catalog URL %q is not https; a signed index fetched in the "+
			"clear invites the substitution the signature exists to catch", address)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := indexClient.Do(request)
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

// Loopback allows plain HTTP only to this machine itself, which is what tests and a local
// notary during development use. Anything reachable over a network keeps the TLS
// requirement.
func Loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if address := net.ParseIP(host); address != nil {
		return address.IsLoopback()
	}
	return false
}
