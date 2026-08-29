package notary

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDC lets a GitHub Actions job publish without a long-lived secret: the job proves "I
// am a workflow of repository X" with the short-lived token GitHub mints for it, and the
// notary checks that claim against the repository the organisation registered.
//
// The token replaces only the publish TOKEN, never the publisher's SIGNATURE. A job that
// authenticates this way still submits a catalog signed by a key the notary pinned, so
// compromising a repository's Actions does not publish — it merely knocks on a door that
// the signature check still guards.

// GitHubIssuer is the issuer GitHub Actions tokens carry.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// DefaultAudience is what the action requests when none is configured. Scoping the
// audience keeps a token minted for some other service from being replayed here.
const DefaultAudience = "skilltrust-notary"

var (
	// ErrOIDC is any failure to accept an OIDC token. One error on purpose, like
	// ErrUnknownOrg: the caller sees 401 either way, and a granular refusal teaches an
	// attacker which check they passed.
	ErrOIDC = errors.New("the OIDC token was not accepted")
)

// OIDCVerifier validates GitHub Actions tokens against the issuer's published keys.
type OIDCVerifier struct {
	Issuer   string
	Audience string
	// JWKSURL overrides discovery, for tests. Empty means <Issuer>/.well-known/jwks.
	JWKSURL string

	mu      sync.Mutex
	keys    map[string]cachedKey
	fetched time.Time
}

// cachedKey is one of the issuer's signing keys and when it was last seen published.
//
// The age matters because the cache merges rather than replaces. A JWKS response that
// transiently omits a key - a partial answer, one server in a rotation, a degraded CDN -
// used to evict a key that was working and reject every token signed with it. Merging fixes
// that and creates the opposite problem: a key the issuer has deliberately withdrawn would
// stay trusted forever. The age bounds it, so a withdrawn key stops being accepted once it
// has gone unseen for MaxKeyAge.
type cachedKey struct {
	key  *rsa.PublicKey
	seen time.Time
}

// MaxKeyAge is how long a signing key stays usable after it was last seen in the issuer's
// JWKS. Long enough to ride out a bad fetch, short enough that a withdrawn key does not
// outlive the day it was withdrawn.
const MaxKeyAge = 24 * time.Hour

// registeredClaims are the ones every issuer sets and VerifyToken decides on.
type registeredClaims struct {
	Issuer    string   `json:"iss"`
	Audience  audience `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
}

// githubClaims adds what a GitHub Actions token carries about the workflow that minted it.
type githubClaims struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Workflow   string `json:"workflow"`
	// SHA is the commit the workflow ran on. GitHub mints it, the publisher does not
	// supply it, which is what makes it usable as the thing an admission check reads:
	// a caller cannot point the check at a commit other than the one it published from.
	SHA string `json:"sha"`
}

// audience tolerates both the string and the array form the spec allows.
type audience []string

func (a *audience) UnmarshalJSON(raw []byte) error {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}
	*a = audience(many)
	return nil
}

// Verify checks the token end to end and returns what it was minted for.
func (v *OIDCVerifier) Verify(token string, now time.Time) (repository, ref, commit string, err error) {
	payload, err := v.VerifyToken(token, now)
	if err != nil {
		return "", "", "", err
	}
	var claims githubClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", "", fmt.Errorf("%w: unreadable claims", ErrOIDC)
	}
	if claims.Repository == "" {
		return "", "", "", fmt.Errorf("%w: no repository claim", ErrOIDC)
	}
	return claims.Repository, claims.Ref, claims.SHA, nil
}

// VerifyToken checks signature, issuer, audience and validity window, and returns the
// claims payload for the caller to read what its issuer puts there. Everything an
// issuer-specific check can rely on has already been decided here; what comes back is
// data from a token that verified, not a token to verify.
func (v *OIDCVerifier) VerifyToken(token string, now time.Time) (json.RawMessage, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWT", ErrOIDC)
	}

	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("%w: unreadable header", ErrOIDC)
	}
	// Pinned to the one algorithm these issuers use. Honouring whatever the header asks
	// for is the classic JWT failure — "alg":"none" and HMAC-with-the-public-key both
	// live there.
	if header.Algorithm != "RS256" {
		return nil, fmt.Errorf("%w: algorithm %q", ErrOIDC, header.Algorithm)
	}

	key, err := v.keyFor(header.KeyID, now)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable signature", ErrOIDC)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", ErrOIDC)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable claims", ErrOIDC)
	}
	var claims registeredClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: unreadable claims", ErrOIDC)
	}

	issuer := v.Issuer
	if issuer == "" {
		issuer = GitHubIssuer
	}
	wanted := v.Audience
	if wanted == "" {
		wanted = DefaultAudience
	}
	if claims.Issuer != issuer {
		return nil, fmt.Errorf("%w: issuer %q", ErrOIDC, claims.Issuer)
	}
	audienceMatched := false
	for _, entry := range claims.Audience {
		if entry == wanted {
			audienceMatched = true
		}
	}
	if !audienceMatched {
		return nil, fmt.Errorf("%w: token was minted for %v, not %q", ErrOIDC, claims.Audience, wanted)
	}
	if claims.Expiry == 0 || now.After(time.Unix(claims.Expiry, 0)) {
		return nil, fmt.Errorf("%w: expired", ErrOIDC)
	}
	if claims.NotBefore != 0 && now.Add(clockSkew).Before(time.Unix(claims.NotBefore, 0)) {
		return nil, fmt.Errorf("%w: not valid yet", ErrOIDC)
	}
	return payload, nil
}

// clockSkew mirrors the catalog's tolerance for clocks that disagree slightly.
const clockSkew = 5 * time.Minute

// keyFor returns the issuer's key, refreshing the JWKS when the id is unknown — which is
// exactly what key rotation looks like — but at most once a minute, so a flood of bad
// key ids cannot turn this endpoint into a JWKS-fetching amplifier.
func (v *OIDCVerifier) keyFor(keyID string, now time.Time) (*rsa.PublicKey, error) {
	if key, ok := v.cached(keyID, now); ok {
		return key, nil
	}

	v.mu.Lock()
	tooSoon := now.Sub(v.fetched) < time.Minute
	if !tooSoon {
		v.fetched = now
	}
	v.mu.Unlock()
	if tooSoon {
		return nil, fmt.Errorf("%w: unknown signing key %q", ErrOIDC, keyID)
	}

	// Fetched outside the lock. Holding it across a ten-second HTTP call meant every
	// concurrent verification queued behind one slow issuer, which behind a gateway that
	// cuts connections at thirty seconds turns a slow JWKS endpoint into an outage.
	fetched, err := v.fetch()
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	if v.keys == nil {
		v.keys = map[string]cachedKey{}
	}
	// Merged, not replaced: see cachedKey. A response missing a key must not withdraw it.
	for id, key := range fetched {
		v.keys[id] = cachedKey{key: key, seen: now}
	}
	for id, entry := range v.keys {
		if now.Sub(entry.seen) > MaxKeyAge {
			delete(v.keys, id)
		}
	}
	entry, ok := v.keys[keyID]
	v.mu.Unlock()

	if ok {
		return entry.key, nil
	}
	return nil, fmt.Errorf("%w: unknown signing key %q", ErrOIDC, keyID)
}

// cached returns a key that is both known and not stale.
func (v *OIDCVerifier) cached(keyID string, now time.Time) (*rsa.PublicKey, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.keys[keyID]
	if !ok || now.Sub(entry.seen) > MaxKeyAge {
		return nil, false
	}
	return entry.key, true
}

// fetch reads the issuer's JWKS. It touches no shared state, so it can run without the
// lock held.
func (v *OIDCVerifier) fetch() (map[string]*rsa.PublicKey, error) {
	address := v.JWKSURL
	if address == "" {
		issuer := v.Issuer
		if issuer == "" {
			issuer = GitHubIssuer
		}
		address = strings.TrimSuffix(issuer, "/") + "/.well-known/jwks"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get(address)
	if err != nil {
		return nil, fmt.Errorf("%w: the issuer's keys are unreachable: %v", ErrOIDC, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: the issuer's keys answered %s", ErrOIDC, response.Status)
	}

	var document struct {
		Keys []struct {
			KeyType  string `json:"kty"`
			KeyID    string `json:"kid"`
			Modulus  string `json:"n"`
			Exponent string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: the issuer's keys are unreadable: %v", ErrOIDC, err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, entry := range document.Keys {
		if entry.KeyType != "RSA" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(entry.Modulus)
		if err != nil {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(entry.Exponent)
		if err != nil {
			continue
		}
		exponent := 0
		for _, b := range exponentBytes {
			exponent = exponent<<8 | int(b)
		}
		if exponent <= 1 {
			continue
		}
		keys[entry.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	}
	if len(keys) == 0 {
		// An answer with no usable key is not an answer. Returning it would merge nothing
		// and look identical to a successful refresh, so the caller would report "unknown
		// key" for a reachable issuer that simply said nothing.
		return nil, fmt.Errorf("%w: the issuer published no usable RSA keys", ErrOIDC)
	}
	return keys, nil
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}
