package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newStatement() Statement {
	return Statement{
		Subject:    Subject{Name: "demo", Digest: "sha256:" + repeat("a", 64)},
		ApprovedBy: "reviewer@example.com",
		ApprovedAt: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
		Notes:      "reviewed line by line",
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for range n {
		out = append(out, s[0])
	}
	return string(out)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	envelope, signed, err := Sign(newStatement(), private)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.PayloadType != PayloadType {
		t.Fatalf("payloadType = %q", envelope.PayloadType)
	}

	verified, keyID, err := Verify(envelope, NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if keyID != KeyID(public) {
		t.Fatalf("keyid = %s", keyID)
	}
	if verified.Subject != signed.Subject || verified.ApprovedBy != signed.ApprovedBy {
		t.Fatalf("statement did not survive the round trip: %+v", verified)
	}
}

func TestSignRequiresAttribution(t *testing.T) {
	_, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(Statement) Statement{
		"no approver": func(s Statement) Statement { s.ApprovedBy = ""; return s },
		"no time":     func(s Statement) Statement { s.ApprovedAt = time.Time{}; return s },
		"no digest":   func(s Statement) Statement { s.Subject.Digest = ""; return s },
		"no name":     func(s Statement) Statement { s.Subject.Name = ""; return s },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Sign(mutate(newStatement()), private); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := Sign(newStatement(), private)
	if err != nil {
		t.Fatal(err)
	}

	// Swap in a statement claiming a different digest, keeping the signature.
	forged := newStatement()
	forged.Version = StatementVersion
	forged.Subject.Digest = "sha256:" + repeat("b", 64)
	payload, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)

	if _, _, err := Verify(envelope, NewTrustedKeys(public)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsUntrustedSigner(t *testing.T) {
	_, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	stranger, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	envelope, _, err := Sign(newStatement(), private)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := Verify(envelope, NewTrustedKeys(stranger)); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("err = %v, want ErrUntrustedKey", err)
	}
}

// The pre-authentication encoding binds the payload type into the signed bytes. Without it
// a signature over an attestation could be presented as a signature over any other
// document that happened to have the same body, which is the classic signature-confusion
// attack.
func TestSignatureCannotBeReplayedUnderAnotherPayloadType(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := Sign(newStatement(), private)
	if err != nil {
		t.Fatal(err)
	}

	envelope.PayloadType = "application/vnd.example.other+json"
	if _, _, err := Verify(envelope, NewTrustedKeys(public)); !errors.Is(err, ErrWrongPayload) {
		t.Fatalf("err = %v, want ErrWrongPayload", err)
	}

	// Even if a verifier were willing to accept the type, the signed bytes differ.
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(public, pae("application/vnd.example.other+json", payload), raw) {
		t.Fatal("a signature verified under a payload type it was not made for")
	}
}

func TestVerifyRejectsAnEnvelopeWithoutSignatures(t *testing.T) {
	public, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope := &Envelope{PayloadType: PayloadType, Payload: "e30="}

	if _, _, err := Verify(envelope, NewTrustedKeys(public)); !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("err = %v, want ErrNoSignatures", err)
	}
}

func TestKeyIDIsStable(t *testing.T) {
	public, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(public) != KeyID(public) {
		t.Fatal("key id is not deterministic")
	}
	other, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(public) == KeyID(other) {
		t.Fatal("two keys share an id")
	}
}

func TestPrivateKeyPermissionsAreEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("see TestPrivateKeyPermissionsAreNotCheckedOnWindows")
	}
	_, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signer.key")
	if err := WritePrivateKey(path, private); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPrivateKey(path); err != nil {
		t.Fatalf("a 0600 key must load: %v", err)
	}

	// A signing key the whole machine can read is a signing key anything running as this
	// user can borrow, so loading it is refused rather than warned about.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("a world-readable signing key must be refused")
	}
}

func TestKeyFilesRoundTrip(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "k.key")
	publicPath := filepath.Join(directory, "k.pub")

	if err := WritePrivateKey(privatePath, private); err != nil {
		t.Fatal(err)
	}
	if err := WritePublicKey(publicPath, public); err != nil {
		t.Fatal(err)
	}

	loadedPrivate, err := LoadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPublic, err := LoadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(loadedPrivate.Public().(ed25519.PublicKey)) != KeyID(loadedPublic) {
		t.Fatal("the key halves do not match after a round trip")
	}
}

// An empty root set can approve nothing. Reading it as a permissive default would turn a
// misconfiguration into blanket acceptance, which is the same failure shape as treating an
// unreadable lock as an absent one.
func TestEmptyTrustedKeySetIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"keys":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustedKeys(path); err == nil {
		t.Fatal("an empty trusted-key set must be refused")
	}
}

func TestTrustedKeyFileRoundTrip(t *testing.T) {
	public, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted.json")
	if err := SaveTrustedKeys(path, map[string]ed25519.PublicKey{"reviewer": public}); err != nil {
		t.Fatal(err)
	}

	trusted, err := LoadTrustedKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Len() != 1 {
		t.Fatalf("len = %d", trusted.Len())
	}
	if _, ok := trusted.Lookup(KeyID(public)); !ok {
		t.Fatal("the saved key is not pinned")
	}
}

func TestEnvelopeFileRoundTrip(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := Sign(newStatement(), private)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "demo.att.json")
	if err := envelope.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEnvelope(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(loaded, NewTrustedKeys(public)); err != nil {
		t.Fatalf("an envelope must verify after a file round trip: %v", err)
	}
}

// Pins the platform gap so it is a tested property rather than a surprise: Windows file
// modes are synthesized from the read-only attribute and say nothing about the ACL, so the
// owner-only check cannot run there.
func TestPrivateKeyPermissionsAreNotCheckedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("describes Windows behaviour")
	}

	_, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signer.key")
	if err := WritePrivateKey(path, private); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err != nil {
		t.Fatalf("Windows carries no usable mode, so the key must still load: %v", err)
	}
}
