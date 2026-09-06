// Package subscription defines the signed configuration behind an axela URI.
// Public subscriptions need no identity. Team reads require an existing machine
// identity; neither descriptor grants reporting permission or installs hooks.
package subscription

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
)

const PayloadType = "application/vnd.skilltrust.subscription.v1+json"
const Origin = "https://axela.app"
const Lifetime = 15 * time.Minute
const MaxBytes = 64 << 10

type Descriptor struct {
	Version       int       `json:"version"`
	Origin        string    `json:"origin"`
	Organisation  string    `json:"organisation"`
	Catalog       string    `json:"catalog"`
	Repository    string    `json:"repository"`
	Ref           string    `json:"ref"`
	Commit        string    `json:"commit"`
	CatalogURL    string    `json:"catalog_url"`
	CatalogDigest string    `json:"catalog_digest"`
	Access        string    `json:"access,omitempty"`
	SourceURL     string    `json:"source_url,omitempty"`
	SourceDigest  string    `json:"source_digest,omitempty"`
	PublisherKeys []string  `json:"publisher_keys"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var repository = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9._-]*\.git$`)
var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// URL resolves names at the fixed service origin, never a caller-supplied host.
func URL(org, catalog string) (string, error) {
	if !name.MatchString(org) || !name.MatchString(catalog) {
		return "", fmt.Errorf("use axela://team/catalog with valid team and catalog names")
	}
	return Origin + "/v1/subscriptions/" + org + "/" + catalog, nil
}

// SourceURL binds authenticated delivery to the exact catalog snapshot.
func SourceURL(org, catalog, catalogDigest string) (string, error) {
	base, err := URL(org, catalog)
	if err != nil || !digest.MatchString(catalogDigest) {
		return "", fmt.Errorf("the source needs an exact catalog identity")
	}
	return base + "/source/" + catalogDigest, nil
}

func ParseURI(raw string) (org, catalog string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "axela" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.Contains(raw, "%") {
		return "", "", fmt.Errorf("use axela://team/catalog")
	}
	org, catalog = u.Host, strings.TrimPrefix(u.Path, "/")
	if raw != "axela://"+org+"/"+catalog {
		return "", "", fmt.Errorf("use axela://team/catalog")
	}
	if _, err := URL(org, catalog); err != nil {
		return "", "", err
	}
	return org, catalog, nil
}

func validRef(ref string) bool {
	branch := strings.TrimPrefix(ref, "refs/heads/")
	if branch == ref {
		branch = strings.TrimPrefix(ref, "refs/tags/")
	}
	if branch == ref || branch == "" || len(ref) > 1024 || strings.ContainsAny(ref, " ~^:?*[\\\t\r\n\x00") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") || strings.HasSuffix(ref, ".") {
		return false
	}
	for _, part := range strings.Split(branch, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	for _, r := range ref {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// Validate checks a descriptor's exact identity and lifetime before it is used
// as a fetch target or signed. It does not authenticate its publisher or notary.
func Validate(d Descriptor, org, catalog string, now time.Time) error {
	if _, err := URL(org, catalog); err != nil {
		return err
	}
	if d.Version != 1 || d.Origin != Origin || d.Organisation != org || d.Catalog != catalog || d.CatalogURL != Origin+"/v1/catalogs/"+org+"/"+catalog {
		return fmt.Errorf("the subscription descriptor belongs to another service or catalog")
	}
	if !repository.MatchString(d.Repository) || strings.Contains(d.Repository, "..") || !validRef(d.Ref) || !commit.MatchString(d.Commit) || !digest.MatchString(d.CatalogDigest) {
		return fmt.Errorf("the subscription descriptor has no exact repository and catalog identity")
	}
	switch d.Access {
	case "":
		if d.SourceURL != "" || d.SourceDigest != "" {
			return fmt.Errorf("public subscriptions cannot carry authenticated source delivery")
		}
	case "team":
		address, err := SourceURL(org, catalog, d.CatalogDigest)
		if err != nil || d.SourceURL != address || !strings.HasPrefix(d.SourceDigest, "sha256:") || !digest.MatchString(strings.TrimPrefix(d.SourceDigest, "sha256:")) {
			return fmt.Errorf("the team subscription has no exact source identity")
		}
	default:
		return fmt.Errorf("the subscription uses an unsupported access mode")
	}
	if d.IssuedAt.IsZero() || d.IssuedAt.After(now.Add(5*time.Minute)) || !d.ExpiresAt.After(now) || !d.ExpiresAt.After(d.IssuedAt) || d.ExpiresAt.Sub(d.IssuedAt) > Lifetime {
		return fmt.Errorf("the subscription descriptor expired or has an invalid lifetime; fetch it again")
	}
	if len(d.PublisherKeys) == 0 {
		return fmt.Errorf("the subscription descriptor has no publisher key")
	}
	seen := map[string]bool{}
	for _, pem := range d.PublisherKeys {
		key, err := attest.ParsePublicKey([]byte(pem))
		if err != nil {
			return fmt.Errorf("the subscription descriptor has an unusable publisher key")
		}
		id := attest.KeyID(key)
		if seen[id] {
			return fmt.Errorf("the subscription descriptor repeats a publisher key")
		}
		seen[id] = true
	}
	return nil
}

func Sign(d Descriptor, keys ...ed25519.PrivateKey) (*attest.Envelope, error) {
	if err := Validate(d, d.Organisation, d.Catalog, time.Now().UTC()); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the subscription descriptor needs a notary signature")
	}
	for _, key := range keys {
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("the subscription descriptor has an unusable notary key")
		}
		for _, pem := range d.PublisherKeys {
			publisher, _ := attest.ParsePublicKey([]byte(pem))
			if attest.KeyID(publisher) == attest.KeyID(key.Public().(ed25519.PublicKey)) {
				return nil, fmt.Errorf("the publisher and notary must use different keys")
			}
		}
	}
	payload, err := json.Marshal(d)
	if err != nil || len(payload) > MaxBytes/2 {
		return nil, fmt.Errorf("the subscription descriptor is too large")
	}
	envelope := attest.SignPayload(PayloadType, payload, keys[0])
	for _, key := range keys[1:] {
		if err := attest.Countersign(envelope, key); err != nil {
			return nil, err
		}
	}
	if raw, err := json.Marshal(envelope); err != nil || len(raw) > MaxBytes {
		return nil, fmt.Errorf("the subscription descriptor is too large")
	}
	return envelope, nil
}

// Verify uses the notary keys already established by the caller. Publisher keys
// inside this descriptor never authenticate the descriptor itself.
func Verify(envelope *attest.Envelope, trusted *attest.TrustedKeys, org, catalog string, now time.Time) (*Descriptor, []string, error) {
	if envelope == nil || trusted == nil {
		return nil, nil, fmt.Errorf("the subscription descriptor needs a trusted notary signature")
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > MaxBytes {
		return nil, nil, fmt.Errorf("the subscription descriptor is too large")
	}
	payload, signers, err := attest.VerifyPayloadSigners(envelope, PayloadType, trusted)
	if err != nil {
		return nil, nil, err
	}
	var d Descriptor
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return nil, nil, fmt.Errorf("the subscription descriptor is unreadable")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, nil, fmt.Errorf("the subscription descriptor is unreadable")
	}
	if err := Validate(d, org, catalog, now); err != nil {
		return nil, nil, err
	}
	for _, pem := range d.PublisherKeys {
		key, _ := attest.ParsePublicKey([]byte(pem))
		if _, sameParty := trusted.Lookup(attest.KeyID(key)); sameParty {
			return nil, nil, fmt.Errorf("the publisher and notary must use different keys")
		}
	}
	return &d, signers, nil
}
