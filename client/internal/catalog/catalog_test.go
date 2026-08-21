package catalog

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
)

func fixture(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return public, private, time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
}

func snapshot(now time.Time, sequence int64, digests ...string) Snapshot {
	entries := make([]Entry, 0, len(digests))
	for _, digest := range digests {
		entries = append(entries, Entry{Digest: digest, RevokedAt: now, Reason: "test"})
	}
	return Snapshot{
		Sequence:   sequence,
		IssuedAt:   now,
		ValidUntil: now.Add(7 * 24 * time.Hour),
		Revoked:    entries,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	public, private, now := fixture(t)

	envelope, err := Sign(snapshot(now, 1, "sha256:aa"), private)
	if err != nil {
		t.Fatal(err)
	}

	verified, keyID, err := Verify(envelope, attest.NewTrustedKeys(public), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != attest.KeyID(public) {
		t.Fatalf("keyid = %s", keyID)
	}
	if entry, revoked := verified.IsRevoked("sha256:aa"); !revoked || entry.Reason != "test" {
		t.Fatalf("digest not revoked: %+v", verified.Revoked)
	}
	if _, revoked := verified.IsRevoked("sha256:bb"); revoked {
		t.Fatal("an unrelated digest must not read as revoked")
	}
}

// Freshness is the whole point of an expiry: a revocation is a claim about the present, so
// a stale catalog cannot answer the question and must not be read as "nothing revoked".
func TestExpiredCatalogIsRefused(t *testing.T) {
	public, private, now := fixture(t)

	envelope, err := Sign(snapshot(now, 1, "sha256:aa"), private)
	if err != nil {
		t.Fatal(err)
	}

	later := now.Add(8 * 24 * time.Hour)
	if _, _, err := Verify(envelope, attest.NewTrustedKeys(public), nil, later); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// Replaying an older catalog is how an attacker un-revokes something without forging
// anything: the old signature is genuine.
func TestRollbackIsRefused(t *testing.T) {
	public, private, now := fixture(t)

	old, err := Sign(snapshot(now, 1), private)
	if err != nil {
		t.Fatal(err)
	}

	state := &State{Sequence: 5}
	if _, _, err := Verify(old, attest.NewTrustedKeys(public), state, now); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("err = %v, want ErrRolledBack", err)
	}

	// The same sequence again is fine: re-reading the current catalog is not an attack.
	current, err := Sign(snapshot(now, 5), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(current, attest.NewTrustedKeys(public), state, now); err != nil {
		t.Fatalf("re-reading the current sequence must be allowed: %v", err)
	}
}

func TestCatalogFromTheFutureIsRefused(t *testing.T) {
	public, private, now := fixture(t)

	envelope, err := Sign(snapshot(now.Add(time.Hour), 1), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(envelope, attest.NewTrustedKeys(public), nil, now); !errors.Is(err, ErrFromFuture) {
		t.Fatalf("err = %v, want ErrFromFuture", err)
	}

	// Ordinary clock drift between two machines must not break verification.
	slight, err := Sign(snapshot(now.Add(time.Minute), 1), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(slight, attest.NewTrustedKeys(public), nil, now); err != nil {
		t.Fatalf("a minute of drift must be tolerated: %v", err)
	}
}

// The payload type is bound into the signed bytes, so the two document kinds this tool
// signs cannot be swapped for one another.
func TestCatalogSignatureIsNotAnAttestation(t *testing.T) {
	public, private, now := fixture(t)

	envelope, err := Sign(snapshot(now, 1), private)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := attest.Verify(envelope, attest.NewTrustedKeys(public)); !errors.Is(err, attest.ErrWrongPayload) {
		t.Fatalf("a catalog verified as an attestation: %v", err)
	}

	attestation, _, err := attest.Sign(attest.Statement{
		Subject:    attest.Subject{Name: "demo", Digest: "sha256:aa"},
		ApprovedBy: "reviewer",
		ApprovedAt: now,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(attestation, attest.NewTrustedKeys(public), nil, now); !errors.Is(err, attest.ErrWrongPayload) {
		t.Fatalf("an attestation verified as a catalog: %v", err)
	}
}

func TestSignRejectsIncoherentSnapshots(t *testing.T) {
	_, private, now := fixture(t)

	cases := map[string]Snapshot{
		"zero sequence":        {Sequence: 0, IssuedAt: now, ValidUntil: now.Add(time.Hour)},
		"expires before issue": {Sequence: 1, IssuedAt: now, ValidUntil: now.Add(-time.Hour)},
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(candidate, private); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestStateNeverGoesBackwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json.state")
	now := time.Now().UTC()

	state, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 0 {
		t.Fatalf("a missing state file must read as sequence zero, got %d", state.Sequence)
	}

	if err := state.Save(path, 4, now); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Sequence != 4 {
		t.Fatalf("sequence = %d", reloaded.Sequence)
	}
	if err := reloaded.Save(path, 3, now); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("err = %v, want ErrRolledBack", err)
	}
}

func TestUnreadableStateIsAnErrorNotAFreshStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json.state")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Treating a corrupt state file as "nothing seen yet" would silently re-enable the
	// rollback it exists to prevent.
	if _, err := LoadState(path); err == nil {
		t.Fatal("a corrupt state file must be an error")
	}
}
