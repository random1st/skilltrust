package subscription

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func descriptorFixture(t *testing.T) Descriptor {
	t.Helper()
	public, _, _ := attest.GenerateKey()
	pem, _ := attest.EncodePublicKey(public)
	now := time.Now().UTC()
	return Descriptor{Version: 1, Origin: Origin, Organisation: "acme", Catalog: "skills", Repository: "https://github.com/acme/skills.git", Ref: "refs/heads/main", Commit: strings.Repeat("a", 40), CatalogURL: Origin + "/v1/catalogs/acme/skills", CatalogDigest: strings.Repeat("b", 64), PublisherKeys: []string{string(pem)}, IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
}

func TestDescriptorBindsCatalogSourceAndNotary(t *testing.T) {
	d := descriptorFixture(t)
	public, key, _ := attest.GenerateKey()
	otherPublic, otherKey, _ := attest.GenerateKey()
	envelope, err := Sign(d, key, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, trusted := range []*attest.TrustedKeys{attest.NewTrustedKeys(public), attest.NewTrustedKeys(otherPublic)} {
		got, signers, err := Verify(envelope, trusted, "acme", "skills", d.IssuedAt)
		if err != nil || len(signers) != 1 || got.CatalogDigest != d.CatalogDigest || got.Commit != d.Commit {
			t.Fatalf("rotation verification = %+v, %v, %v", got, signers, err)
		}
	}
	for _, identity := range [][2]string{{"other", "skills"}, {"acme", "other"}} {
		if _, _, err := Verify(envelope, attest.NewTrustedKeys(public), identity[0], identity[1], d.IssuedAt); err == nil {
			t.Fatal("descriptor was replayed for another identity")
		}
	}
	if _, _, err := Verify(nil, attest.NewTrustedKeys(public), "acme", "skills", d.IssuedAt); err == nil {
		t.Fatal("nil descriptor accepted")
	}
	if _, _, err := Verify(envelope, nil, "acme", "skills", d.IssuedAt); err == nil {
		t.Fatal("missing notary trust accepted")
	}
}

func TestDescriptorRefusesUnsafeOrStaleConfiguration(t *testing.T) {
	public, key, _ := attest.GenerateKey()
	notaryPEM, _ := attest.EncodePublicKey(public)
	for label, change := range map[string]func(*Descriptor){
		"version":               func(d *Descriptor) { d.Version = 2 },
		"origin":                func(d *Descriptor) { d.Origin = "https://evil.test" },
		"catalog redirect":      func(d *Descriptor) { d.CatalogURL += "?next=evil" },
		"credential repository": func(d *Descriptor) { d.Repository = "https://token@github.com/acme/skills.git" },
		"repository traversal":  func(d *Descriptor) { d.Repository = "https://github.com/acme/../skills.git" },
		"ref option":            func(d *Descriptor) { d.Ref = "--upload-pack=evil" },
		"ref traversal":         func(d *Descriptor) { d.Ref = "refs/heads/../main" },
		"commit":                func(d *Descriptor) { d.Commit = "main" },
		"digest":                func(d *Descriptor) { d.CatalogDigest = "sha256:" + d.CatalogDigest },
		"no publisher":          func(d *Descriptor) { d.PublisherKeys = nil },
		"repeated publisher":    func(d *Descriptor) { d.PublisherKeys = append(d.PublisherKeys, d.PublisherKeys[0]) },
		"same party":            func(d *Descriptor) { d.PublisherKeys = []string{string(notaryPEM)} },
		"expired":               func(d *Descriptor) { d.ExpiresAt = d.IssuedAt },
		"future":                func(d *Descriptor) { d.IssuedAt = d.IssuedAt.Add(time.Hour); d.ExpiresAt = d.IssuedAt.Add(Lifetime) },
		"unbounded":             func(d *Descriptor) { d.ExpiresAt = d.IssuedAt.Add(Lifetime + time.Second) },
	} {
		t.Run(label, func(t *testing.T) {
			d := descriptorFixture(t)
			now := d.IssuedAt
			change(&d)
			payload, _ := json.Marshal(d)
			envelope := attest.SignPayload(PayloadType, payload, key)
			if _, _, err := Verify(envelope, attest.NewTrustedKeys(public), "acme", "skills", now); err == nil {
				t.Fatal("unsafe descriptor accepted")
			}
		})
	}
}

func TestAxelaURIHasOneFixedOriginAndExactIdentity(t *testing.T) {
	org, catalog, err := ParseURI("axela://acme/skills")
	if err != nil || org != "acme" || catalog != "skills" {
		t.Fatalf("parse = %q, %q, %v", org, catalog, err)
	}
	got, err := URL(org, catalog)
	if err != nil || got != "https://axela.app/v1/subscriptions/acme/skills" {
		t.Fatalf("URL = %q, %v", got, err)
	}
	for _, bad := range []string{"https://acme/skills", "axela://acme", "axela://acme/skills/", "axela://acme/a/b", "axela://user@acme/skills", "axela://acme:443/skills", "axela://acme/skills?", "axela://acme/skills?q=x", "axela://acme/skills#x", "axela://acme/%73kills", "axela://acme/../skills", "axela://acme/skills#", "AXELA://acme/skills"} {
		if _, _, err := ParseURI(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDescriptorRejectsUnknownOrTrailingPayloadFields(t *testing.T) {
	d := descriptorFixture(t)
	public, key, _ := attest.GenerateKey()
	payload, _ := json.Marshal(d)
	for _, raw := range []string{string(payload) + `{}`, strings.TrimSuffix(string(payload), "}") + `,"report_url":"https://evil.test"}`} {
		envelope := attest.SignPayload(PayloadType, []byte(raw), key)
		if _, _, err := Verify(envelope, attest.NewTrustedKeys(public), "acme", "skills", d.IssuedAt); err == nil {
			t.Fatal("ambiguous descriptor schema accepted")
		}
	}
}
