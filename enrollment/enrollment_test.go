package enrollment

import (
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func TestEnrollmentBindsPossessionServiceAndLifetime(t *testing.T) {
	_, key, _ := attest.GenerateKey()
	now := time.Now().UTC()
	request := Request{Audience: "https://axela.app", Nonce: strings.Repeat("ab", 32), TokenDigest: strings.Repeat("cd", 32), Machine: "Work laptop", IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
	env, err := Sign(request, key)
	if err != nil {
		t.Fatal(err)
	}
	got, signer, err := Verify(env, request.Audience, now)
	if err != nil || signer == "" || got.Machine != request.Machine {
		t.Fatalf("valid proof: %v", err)
	}
	if _, _, err := Verify(env, "https://other.example", now); err == nil {
		t.Fatal("accepted another audience")
	}
	if _, _, err := Verify(env, request.Audience, now.Add(Lifetime)); err == nil {
		t.Fatal("accepted expired consent")
	}
	env.Signatures[0].Sig = strings.Repeat("x", len(env.Signatures[0].Sig))
	if _, _, err := Verify(env, request.Audience, now); err == nil {
		t.Fatal("accepted forged possession")
	}
}

func TestEnrollmentRejectsLongLivedAndMalformedRequests(t *testing.T) {
	_, key, _ := attest.GenerateKey()
	now := time.Now().UTC()
	base := Request{Audience: "https://axela.app", Nonce: strings.Repeat("ab", 32), TokenDigest: strings.Repeat("cd", 32), Machine: "Laptop", IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.ExpiresAt = now.Add(24 * time.Hour) },
		func(r *Request) { r.IssuedAt = now.Add(5 * time.Minute) },
		func(r *Request) { r.Nonce = "guessable" },
		func(r *Request) { r.TokenDigest = "credential" },
		func(r *Request) { r.Machine = "" },
	} {
		r := base
		mutate(&r)
		env, _ := Sign(r, key)
		if _, _, err := Verify(env, base.Audience, now); err == nil {
			t.Fatalf("accepted invalid request: %+v", r)
		}
	}
}

func TestConnectionOrigin(t *testing.T) {
	for _, bad := range []string{"https://:443", "http://axela.app", "https://u:p@axela.app", "https://axela.app/other", "https://axela.app?next=x", "file:///tmp", "https://axela.app#x"} {
		if _, err := BaseURL(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, good := range []string{"https://axela.app", "https://example.com/", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := BaseURL(good); err != nil {
			t.Fatalf("refused %s: %v", good, err)
		}
	}
}
