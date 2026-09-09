package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
	"a deliberate re-key after the previous signing key was lost; the sequence still advances " +
	"and revocations that only the old index carried are dropped"

// priorIndex is what is already published beside a repository, and how it was read.
//
// Bypassed and Dropped exist so the commands can say what actually happened rather than
// what was asked for. Deriving "did we re-key?" from the flag was wrong twice over: it
// announced a substitution when the key turned out to verify after all, and it stayed
// silent on the path where a signature really was bypassed.
type priorIndex struct {
	Sequence int64
	Revoked  []catalog.Entry
	// Bypassed records that the existing signature could not be verified and -rekey
	// allowed it anyway. This, not the flag, is the fact worth printing.
	Bypassed bool
	// Dropped is how many revocations the unverifiable index carried and this signature
	// does not. A kill-switch that lived only as a catalog claim does not survive a lost
	// key, and the operator has to be told to re-assert it rather than discover it.
	Dropped int
}

// ErrNoPreviousSequence is refusing to guess. An index that exists but cannot be read is
// not the same as no index at all, and treating it as a first publish is precisely the
// outage this whole change exists to prevent: the sequence restarts at 1 and every
// subscriber that already saw a higher number refuses the chain forever.
var ErrNoPreviousSequence = errors.New("an index is already published here but its sequence could not be read")

// previousSnapshot reads what is already published so a new signature can carry it
// forward. It returns nil, with no error, only when nothing is published yet.
//
// When rekeying, the existing envelope is read without checking its signature. The only
// value taken is the sequence, and it is used to pick the next one. That is deliberately
// narrow, and the bound is smaller than it first looks: whoever can rewrite this file is
// already standing on the machine that signs, and can delete it outright. What the
// unverified read buys is that no consumer and no notary is asked to go backwards.
//
// It is not, however, a guarantee that the number only goes up — an earlier version of
// this comment claimed that, and it was wrong. A hostile or truncated payload can carry a
// zero, a negative, or a value at the ceiling where +1 wraps. So the recovered number is
// range-checked here rather than trusted, and an unusable one is an error, never a silent
// restart.
func previousSnapshot(indexPath string, key ed25519.PrivateKey, rekey bool) (*priorIndex, error) {
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
		if seqErr := usableSequence(previous.Sequence); seqErr != nil {
			return nil, seqErr
		}
		return &priorIndex{Sequence: previous.Sequence, Revoked: previous.Revoked}, nil
	}
	if !rekey {
		return nil, err
	}
	// Signed by somebody this key is not. Everything except the sequence is dropped,
	// revocations included, because carrying a claim forward out of an envelope this
	// publisher cannot verify would be signing for a statement they did not make.
	//
	// Decoded by hand rather than through catalog.Open, which verifies and is right to.
	// Reading a payload without checking who wrote it is a thing that should be visible in
	// the code doing it, not hidden behind a nil argument to a function whose job is to
	// check.
	body, decodeErr := base64.StdEncoding.DecodeString(existing.Payload)
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPreviousSequence, decodeErr)
	}
	var unverified catalog.Snapshot
	if unmarshalErr := json.Unmarshal(body, &unverified); unmarshalErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPreviousSequence, unmarshalErr)
	}
	if seqErr := usableSequence(unverified.Sequence); seqErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPreviousSequence, seqErr)
	}
	return &priorIndex{
		Sequence: unverified.Sequence,
		Bypassed: true,
		Dropped:  len(unverified.Revoked),
	}, nil
}

// usableSequence rejects a number the next signature cannot be built on. Zero and negative
// mean the field was absent or garbage; the ceiling means +1 wraps into a negative
// sequence, which every consumer would read as an enormous rollback.
func usableSequence(sequence int64) error {
	if sequence < 1 {
		return fmt.Errorf("sequence %d is not a published sequence", sequence)
	}
	if sequence == math.MaxInt64 {
		return fmt.Errorf("sequence %d cannot be advanced without wrapping", sequence)
	}
	return nil
}

// failPrevious refuses, and names the actual reason.
//
// Three different things reach here and only one of them is answered by -rekey. Offering
// the flag for all three would send somebody with a permission error, or with a corrupt
// file, to a command that cannot help — and, worse, would teach them to reach for the one
// override in this tool whenever anything goes wrong with a signature.
func failPrevious(what, indexPath string, err error, rekey bool) int {
	switch {
	case errors.Is(err, ErrNoPreviousSequence):
		fmt.Fprintf(os.Stderr,
			"skillctl: %v\n           at %s\n"+
				"           signing anyway would restart the sequence, and every subscriber "+
				"that already saw a higher one would refuse this catalog from then on\n",
			err, indexPath)
	case rekey:
		// -rekey was given and the failure was not the signature, so this is not the
		// situation the flag is for.
		fmt.Fprintf(os.Stderr, "skillctl: %s at %s could not be read: %v\n", what, indexPath, err)
	default:
		fmt.Fprintf(os.Stderr,
			"skillctl: refusing to replace %s this key cannot verify: %v\n"+
				"           if the key that signed it is gone, say so: -rekey\n", what, err)
	}
	return exitUsage
}

// reportRekey says out loud what a re-key did, because it is the one path here that
// replaces a signer, and a person who ran it should not have to read a file to find out.
// Driven by what happened, not by what was asked: passing -rekey to a catalog this key can
// verify perfectly well is not a re-key and must not claim to be one.
func reportRekey(previous *priorIndex, sequence int64) {
	if previous == nil || !previous.Bypassed {
		return
	}
	fmt.Printf("re-keyed    a different key signed the previous index; "+
		"consumers must pin this key again and follow from sequence %d\n", sequence)
	if previous.Dropped > 0 {
		fmt.Printf("dropped     %d revocation%s only the old index carried; "+
			"re-assert any that still apply with `skillctl catalog revoke`\n",
			previous.Dropped, plural(previous.Dropped, "", "s"))
	}
}
