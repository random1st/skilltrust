package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func TestReadProofBindsMachineMethodAndExactResource(t *testing.T) {
	public, key, _ := attest.GenerateKey()
	other, _, _ := attest.GenerateKey()
	now := time.Now().UTC()
	archive, _ := SourceURL("acme", "skills", strings.Repeat("a", 64))
	addresses := []string{Origin + "/v1/subscriptions/acme/skills", Origin + "/v1/catalogs/acme/skills", archive}
	for _, address := range addresses {
		header, err := SignRead(http.MethodGet, address, key, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRead(header, http.MethodGet, address, attest.NewTrustedKeys(public), now); err != nil {
			t.Fatal(err)
		}
		for label, check := range map[string]error{
			"wrong machine":   VerifyRead(header, http.MethodGet, address, attest.NewTrustedKeys(other), now),
			"wrong method":    VerifyRead(header, http.MethodPut, address, attest.NewTrustedKeys(public), now),
			"another team":    VerifyRead(header, http.MethodGet, strings.Replace(address, "/acme/", "/other/", 1), attest.NewTrustedKeys(public), now),
			"another catalog": VerifyRead(header, http.MethodGet, strings.Replace(address, "/skills", "/other", 1), attest.NewTrustedKeys(public), now),
			"expired":         VerifyRead(header, http.MethodGet, address, attest.NewTrustedKeys(public), now.Add(ReadLifetime)),
			"future":          VerifyRead(header, http.MethodGet, address, attest.NewTrustedKeys(public), now.Add(-time.Minute)),
			"no key":          VerifyRead(header, http.MethodGet, address, nil, now),
		} {
			if check == nil {
				t.Errorf("accepted %s", label)
			}
		}
		for _, different := range addresses {
			if different != address && VerifyRead(header, http.MethodGet, different, attest.NewTrustedKeys(public), now) == nil {
				t.Fatal("proof was replayed on another read route")
			}
		}
	}
}

func TestReadProofRejectsAmbiguousOrForeignDestinations(t *testing.T) {
	_, key, _ := attest.GenerateKey()
	good := Origin + "/v1/catalogs/acme/skills"
	for _, address := range []string{
		good + "?", good + "?token=x", good + "#", good + "/", good + "#fragment",
		Origin + "/v1/catalogs/acme/%73kills", Origin + "/v1/catalogs/acme/../skills",
		Origin + "/v1/keys", Origin + "/v1/events/acme", "http://axela.app/v1/catalogs/acme/skills",
		"https://token@axela.app/v1/catalogs/acme/skills", "https://axela.app:443/v1/catalogs/acme/skills",
		"https://evil.test/v1/catalogs/acme/skills", Origin + "/v1/subscriptions/acme/skills/source/main",
	} {
		if _, err := SignRead(http.MethodGet, address, key, time.Now()); err == nil {
			t.Errorf("signed foreign or ambiguous destination %s", address)
		}
	}
}

func TestReadProofRejectsForgedOrUnboundedPayloads(t *testing.T) {
	public, key, _ := attest.GenerateKey()
	now := time.Now().UTC()
	address := Origin + "/v1/catalogs/acme/skills"
	base := readProof{Version: 1, Method: http.MethodGet, URL: address, IssuedAt: now, ExpiresAt: now.Add(ReadLifetime)}
	for label, change := range map[string]func(*readProof){
		"version":     func(p *readProof) { p.Version = 2 },
		"method":      func(p *readProof) { p.Method = http.MethodPost },
		"resource":    func(p *readProof) { p.URL += "?x=1" },
		"zero issued": func(p *readProof) { p.IssuedAt = time.Time{} },
		"long lease":  func(p *readProof) { p.ExpiresAt = now.Add(time.Hour) },
		"reversed":    func(p *readProof) { p.ExpiresAt = now.Add(-time.Second) },
	} {
		t.Run(label, func(t *testing.T) {
			p := base
			change(&p)
			payload, _ := json.Marshal(p)
			raw, _ := json.Marshal(attest.SignPayload(ReadPayloadType, payload, key))
			if VerifyRead(base64.RawURLEncoding.EncodeToString(raw), http.MethodGet, address, attest.NewTrustedKeys(public), now) == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	for _, raw := range []string{"not-json", "null", "{}", strings.Repeat("a", maxReadProofBytes+1)} {
		if VerifyRead(raw, http.MethodGet, address, attest.NewTrustedKeys(public), now) == nil {
			t.Fatal("malformed header accepted")
		}
	}
	payload, _ := json.Marshal(base)
	for _, p := range []string{string(payload) + `{}`, strings.TrimSuffix(string(payload), "}") + `,"scope":"admin"}`} {
		raw, _ := json.Marshal(attest.SignPayload(ReadPayloadType, []byte(p), key))
		if VerifyRead(base64.RawURLEncoding.EncodeToString(raw), http.MethodGet, address, attest.NewTrustedKeys(public), now) == nil {
			t.Fatal("ambiguous payload accepted")
		}
	}
}

func TestTeamDescriptorBindsCatalogAndDeliveredSource(t *testing.T) {
	d := descriptorFixture(t)
	d.Access = "team"
	d.SourceURL, _ = SourceURL(d.Organisation, d.Catalog, d.CatalogDigest)
	d.SourceDigest = "sha256:" + strings.Repeat("c", 64)
	public, key, _ := attest.GenerateKey()
	envelope, err := Sign(d, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify(envelope, attest.NewTrustedKeys(public), d.Organisation, d.Catalog, d.IssuedAt)
	if err != nil || got.Access != "team" || got.SourceDigest != d.SourceDigest || got.SourceURL != d.SourceURL {
		t.Fatalf("team descriptor = %+v, %v", got, err)
	}
	for label, change := range map[string]func(*Descriptor){
		"unknown mode":     func(d *Descriptor) { d.Access = "private" },
		"downgrade":        func(d *Descriptor) { d.Access = "" },
		"no source":        func(d *Descriptor) { d.SourceURL = "" },
		"foreign source":   func(d *Descriptor) { d.SourceURL = "https://evil.test/source" },
		"another snapshot": func(d *Descriptor) { d.CatalogDigest = strings.Repeat("e", 64) },
		"another team":     func(d *Descriptor) { d.SourceURL = strings.Replace(d.SourceURL, "/acme/", "/other/", 1) },
		"no digest":        func(d *Descriptor) { d.SourceDigest = "" },
		"bare digest":      func(d *Descriptor) { d.SourceDigest = strings.TrimPrefix(d.SourceDigest, "sha256:") },
		"upper digest":     func(d *Descriptor) { d.SourceDigest = strings.ToUpper(d.SourceDigest) },
	} {
		t.Run(label, func(t *testing.T) {
			bad := d
			change(&bad)
			payload, _ := json.Marshal(bad)
			envelope := attest.SignPayload(PayloadType, payload, key)
			if _, _, err := Verify(envelope, attest.NewTrustedKeys(public), d.Organisation, d.Catalog, d.IssuedAt); err == nil {
				t.Fatal("invalid source binding accepted")
			}
		})
	}
}
