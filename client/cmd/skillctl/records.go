package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/lockfile"
)

// attestationStore is where this machine keeps the signed approvals it has been given.
//
// They live in the skilltrust home rather than in the skills tree on purpose. An approval
// stored beside the thing it approves is deleted by whatever deletes that thing, and the one
// record an attacker cannot forge is not one to leave inside the directory they are editing.
func attestationStore() string { return filepath.Join(Home(), attest.StoreDirectory) }

// loadRecords gathers everything that says what the skills under root should contain.
//
// Absent records are ordinary: not every tree is pinned, not every skill is signed, and a
// machine that has never run `init` has no pinned keys at all. Unreadable ones are not, and
// are returned as notes for the caller to treat as "could not check" rather than "nothing to
// check" — the distinction the exit codes exist for.
func loadRecords(root string) (lockfile.Records, []string, error) {
	records := lockfile.Records{LockPath: filepath.Join(root, lockfile.FileName)}
	var notes []string

	lock, err := lockfile.Load(records.LockPath)
	switch {
	case err == nil:
		records.Lock = lock
	case !os.IsNotExist(err):
		return records, nil, err
	}

	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if os.IsNotExist(err) {
		// No pinned keys means no signature can be checked at all. Say so only when there
		// are attestations that would otherwise have been used; otherwise it is just a
		// machine that has not been set up, and warning about it every run trains the
		// reader to ignore the warning.
		if _, statErr := os.Stat(attestationStore()); statErr == nil {
			notes = append(notes, fmt.Sprintf("%s holds attestations but %s has no pinned "+
				"keys, so no signature could be checked; run `skillctl init`",
				attestationStore(), Home()))
		}
		return records, notes, nil
	}
	if err != nil {
		return records, nil, err
	}

	approvals, storeNotes, err := attest.LoadStore(attestationStore(), trusted)
	if err != nil {
		return records, nil, err
	}
	notes = append(notes, storeNotes...)

	if len(approvals) > 0 {
		records.Notarized = make(map[string]lockfile.Notarization, len(approvals))
		for name, approval := range approvals {
			records.Notarized[name] = lockfile.Notarization{
				Digest: approval.Digest, ApprovedBy: approval.ApprovedBy, KeyID: approval.KeyID,
			}
		}
	}
	return records, notes, nil
}

// hasRecords reports whether anything says what *this tree* should contain, which is what
// decides between "nothing to check here" and "check it".
//
// Only records that live in the tree count. The approval store is machine-wide, so a signed
// approval existing somewhere is not evidence that this directory is under management —
// treating it as such made every directory on the machine look like a managed tree. `setup`
// writes a lock alongside the signatures precisely so a notarized tree still answers yes.
func hasRecords(root string) bool {
	if _, err := os.Stat(filepath.Join(root, lockfile.FileName)); err == nil {
		return true
	}
	return hasReceipts(root)
}
