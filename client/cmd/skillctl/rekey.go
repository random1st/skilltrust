package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

// Signing again with a key that did not sign before.
//
// Refusing that outright is right for the accident it exists to catch: a publisher on the
// wrong machine, or with the wrong key selected, would otherwise substitute the publisher
// of a catalog other people follow, and nothing would say so.
//
// It was also, until now, the whole answer. A publisher who genuinely lost the old key —
// which happened here, to us — had no way through the check at all, so the real procedure
// became "delete the signed file and sign a fresh one". That is worse in every direction:
// it is undocumented, it leaves no trace of having been a re-key rather than a first
// publish, and it is byte-for-byte indistinguishable from the substitution the check is
// there to stop.
//
// So the deliberate case gets a name and a flag. The check stays exactly as strict when
// nobody asked for it.

// rekeyFlagUsage is the same sentence wherever the flag appears, because the two commands
// that offer it are the same decision made about two file layouts.
const rekeyFlagUsage = "sign with this key even though it did not sign the existing index — " +
	"a deliberate re-key after the previous signing key was lost; the sequence still advances"

// previousSnapshot reads what is already published beside a repository so a new signature
// can carry it forward. It returns nil when nothing is published yet.
//
// When rekeying, the existing envelope is read without checking its signature. That sounds
// worse than it is, and the alternative is worse still: the only thing taken from it is the
// sequence, and it is used to pick a *higher* number. An attacker who can edit this file
// can only push the next sequence up, never down — and they are already standing on the
// machine that signs. What it buys is that no consumer and no notary is ever asked to go
// backwards, which is the failure a lost key otherwise guarantees.
func previousSnapshot(indexPath string, key ed25519.PrivateKey, rekey bool) (*catalog.Snapshot, error) {
	existing, err := attest.LoadEnvelope(indexPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	previous, _, err := catalog.Open(existing,
		attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)))
	if err == nil {
		return previous, nil
	}
	if !rekey {
		return nil, fmt.Errorf("%w", err)
	}
	// Signed by somebody this key is not. Everything except the sequence is dropped:
	// revocations included, because carrying a claim forward out of an envelope this
	// publisher cannot verify would be signing for a statement they did not make.
	//
	// Decoded by hand rather than through catalog.Open, which verifies and is right to.
	// Reading a payload without checking who wrote it is a thing that should be visible
	// in the code doing it, not hidden behind a nil argument to a function whose job is
	// to check.
	body, decodeErr := base64.StdEncoding.DecodeString(existing.Payload)
	if decodeErr != nil {
		return nil, nil
	}
	var unverified catalog.Snapshot
	if json.Unmarshal(body, &unverified) != nil {
		return nil, nil
	}
	return &catalog.Snapshot{Sequence: unverified.Sequence}, nil
}

// reportRekey says out loud what a re-key did, because it is the one path here that
// replaces a signer, and a person who ran it should not have to read a file to find out.
func reportRekey(rekey bool, sequence int64) {
	if !rekey {
		return
	}
	fmt.Printf("re-keyed    a different key signed the previous index; "+
		"consumers must pin this key again and follow from sequence %d\n", sequence)
}
