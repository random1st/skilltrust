// Package enrollment defines the public proof used to connect a computer through
// an existing browser session. Private keys and ingest tokens never leave the client.
package enrollment

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
)

const PayloadType = "application/vnd.skilltrust.enrollment.v1+json"
const Lifetime = 15 * time.Minute
const MaxBytes = 8192

type Request struct {
	Version     int       `json:"version"`
	Audience    string    `json:"audience"`
	Nonce       string    `json:"nonce"`
	PublicKey   string    `json:"public_key"`
	Machine     string    `json:"machine"`
	TokenDigest string    `json:"token_digest"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Catalog struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Ref        string `json:"ref,omitempty"`
	URL        string `json:"url"`
}

// Connection contains public configuration only. Receiving it is not evidence
// that a computer has checked anything; that requires a separate check receipt.
type Connection struct {
	Organisation  string    `json:"organisation"`
	MachineKeyID  string    `json:"machine_key_id"`
	IngestURL     string    `json:"ingest_url"`
	DashboardURL  string    `json:"dashboard_url"`
	PublisherKeys []string  `json:"publisher_keys"`
	NotaryKeys    []string  `json:"notary_keys"`
	Catalogs      []Catalog `json:"catalogs"`
}

// BaseURL rejects credentials, insecure remote hosts, and paths that could turn
// the approval redirect into a different endpoint.
func BaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("use the HTTPS address of your Axela service")
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return "", fmt.Errorf("use HTTPS to connect this computer")
	}
	u.Path = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func Sign(request Request, key ed25519.PrivateKey) (*attest.Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unusable machine key")
	}
	request.Version = 1
	public, err := attest.EncodePublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	request.PublicKey = string(public)
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return attest.SignPayload(PayloadType, payload, key), nil
}

// Verify proves possession, bounds the request's lifetime, and binds consent to
// the service shown in the browser. The self-signed public key authorizes no org.
func Verify(envelope *attest.Envelope, audience string, now time.Time) (*Request, string, error) {
	if envelope == nil {
		return nil, "", fmt.Errorf("start again with skillctl connect")
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > MaxBytes {
		return nil, "", fmt.Errorf("connection request is too large")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("connection request is unreadable")
	}
	var request Request
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, "", fmt.Errorf("connection request is unreadable")
	}
	key, err := attest.ParsePublicKey([]byte(request.PublicKey))
	if err != nil {
		return nil, "", fmt.Errorf("connection request has no usable public key")
	}
	if _, _, err := attest.VerifyPayload(envelope, PayloadType, attest.NewTrustedKeys(key)); err != nil {
		return nil, "", err
	}
	base, err := BaseURL(request.Audience)
	if err != nil || base != audience || request.Audience != base || request.Version != 1 {
		return nil, "", fmt.Errorf("connection request belongs to another service; run skillctl connect again")
	}
	if request.IssuedAt.After(now.Add(time.Minute)) || !request.ExpiresAt.After(now) || request.ExpiresAt.Sub(request.IssuedAt) > Lifetime || !request.ExpiresAt.After(request.IssuedAt) {
		return nil, "", fmt.Errorf("connection request expired; run skillctl connect again")
	}
	for _, value := range []string{request.Nonce, request.TokenDigest} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
			return nil, "", fmt.Errorf("connection request has an invalid identifier")
		}
	}
	if len(request.Machine) == 0 || len(request.Machine) > 100 || strings.ContainsAny(request.Machine, "\r\n\x00") {
		return nil, "", fmt.Errorf("give this computer a short name")
	}
	return &request, attest.KeyID(key), nil
}

// ID uses the signed payload so harmless JSON formatting changes do not create
// a second approval. The signature is always verified before this id is used.
func ID(envelope *attest.Envelope) string {
	sum := sha256.Sum256([]byte(envelope.PayloadType + "\x00" + envelope.Payload))
	return hex.EncodeToString(sum[:])
}
