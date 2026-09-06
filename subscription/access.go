package subscription

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
)

const ReadProofHeader = "X-Axela-Proof"
const ReadPayloadType = "application/vnd.skilltrust.catalog-read.v1+json"
const ReadLifetime = time.Minute
const maxReadProofBytes = 8192

type readProof struct {
	Version   int       `json:"version"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// readAddress accepts only the fixed service's three catalog read routes. In
// particular a proof cannot authorize a write, a key endpoint, or a redirect.
func readAddress(method, address string) bool {
	if method != http.MethodGet {
		return false
	}
	u, err := url.Parse(address)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Scheme+"://"+u.Host != Origin {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || !name.MatchString(parts[2]) || !name.MatchString(parts[3]) {
		return false
	}
	var expected string
	switch {
	case len(parts) == 4 && parts[1] == "catalogs":
		expected = Origin + "/v1/catalogs/" + parts[2] + "/" + parts[3]
	case len(parts) == 4 && parts[1] == "subscriptions":
		expected, _ = URL(parts[2], parts[3])
	case len(parts) == 6 && parts[1] == "subscriptions" && parts[4] == "source":
		expected, _ = SourceURL(parts[2], parts[3], parts[5])
	default:
		return false
	}
	return expected != "" && address == expected
}

// SignRead proves possession of the enrolled machine key. The bearer token is
// sent separately to select that machine in a fresh membership lookup; neither
// credential is a substitute for the other. Proofs intentionally last one minute
// and can be replayed only for the same read while access remains active.
func SignRead(method, address string, key ed25519.PrivateKey, now time.Time) (string, error) {
	if !readAddress(method, address) || len(key) != ed25519.PrivateKeySize || now.IsZero() {
		return "", fmt.Errorf("catalog access needs an exact Axela read and a machine key")
	}
	now = now.UTC()
	payload, err := json.Marshal(readProof{Version: 1, Method: method, URL: address, IssuedAt: now, ExpiresAt: now.Add(ReadLifetime)})
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(attest.SignPayload(ReadPayloadType, payload, key))
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString(raw)
	if len(header) > maxReadProofBytes {
		return "", fmt.Errorf("catalog access proof is too large")
	}
	return header, nil
}

// VerifyRead receives only the exact machine key selected by the caller's live
// authorization check. A cached organisation-wide keyset is not sufficient.
func VerifyRead(header, method, address string, trusted *attest.TrustedKeys, now time.Time) error {
	refused := fmt.Errorf("catalog access proof is missing, invalid, or expired")
	if trusted == nil || now.IsZero() || !readAddress(method, address) || len(header) == 0 || len(header) > maxReadProofBytes {
		return refused
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return refused
	}
	var envelope attest.Envelope
	if strictJSON(raw, &envelope) != nil {
		return refused
	}
	payload, _, err := attest.VerifyPayloadSigners(&envelope, ReadPayloadType, trusted)
	if err != nil {
		return refused
	}
	var proof readProof
	if strictJSON(payload, &proof) != nil || proof.Version != 1 || proof.Method != method || proof.URL != address || proof.IssuedAt.IsZero() || proof.IssuedAt.After(now.Add(15*time.Second)) || !proof.ExpiresAt.After(now) || !proof.ExpiresAt.After(proof.IssuedAt) || proof.ExpiresAt.Sub(proof.IssuedAt) > ReadLifetime {
		return refused
	}
	return nil
}

func strictJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}
