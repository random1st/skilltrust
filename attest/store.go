package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// StoreDirectory is where a machine keeps the attestations it has been given, one file per
// approved copy of a skill. Keeping them outside the skills tree is deliberate: an approval
// that lives beside the thing it approves is deleted by whatever deletes that thing.
const StoreDirectory = "attestations"

// StorePath is the file for one skill directory's attestation inside a store.
//
// The file is keyed by the skill's name plus a hash of where it lives, not by the name
// alone. Keyed by name, signing one skill silently destroyed the approval of any other
// skill that happened to share it — which a real machine does have: a vendor-shipped
// skill-creator beside a hand-written one. Re-signing the same directory still replaces
// its own file, which is what re-approving after a change should do; a different directory
// gets a file of its own.
func StorePath(directory, name, skillDirectory string) string {
	// Canonicalised, because the same directory reached two ways must key one file: on
	// macOS alone, /var and /private/var are one place with two spellings.
	absolute, err := filepath.Abs(skillDirectory)
	if err != nil {
		absolute = skillDirectory
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	sum := sha256.Sum256([]byte(absolute))
	return filepath.Join(directory, name+"-"+hex.EncodeToString(sum[:4])+".att.json")
}

// Approval is a verified signed statement about one skill, reduced to what a caller
// comparing bytes needs. The signature has already been checked against the pinned keys by
// the time one of these exists.
type Approval struct {
	Name       string
	Digest     string
	ApprovedBy string
	KeyID      string
}

// LoadStore reads every attestation in a directory and returns the ones that verify against
// the pinned keys, indexed by the skill they name. A name can carry several approvals: a
// machine really does hold two different skills called the same thing — an adapty-cli in
// ~/.agents/skills and another in ~/.codex/skills — and returning one approval per name
// forced a choice between them that accused whichever lost of drifting from an approval
// that was never about it.
//
// Failures are returned as notes rather than dropped. An attestation that does not verify is
// the single most interesting file in the store — it is either corrupt or forged — and a
// loader that silently skips it turns the strongest available signal into an absence, which
// reads as "this skill was never approved" and is acted on as though nobody had ever signed
// anything. A missing directory is different, and is not a failure: it means no approvals
// have been given yet.
func LoadStore(directory string, trusted *TrustedKeys) (map[string][]Approval, []string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	approvals := map[string][]Approval{}
	var notes []string

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		path := filepath.Join(directory, name)
		envelope, err := LoadEnvelope(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s could not be read: %v", path, err))
			continue
		}
		statement, keyID, err := Verify(envelope, trusted)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s does not verify against your pinned keys, "+
				"so it was not used: %v", path, err))
			continue
		}
		if statement.Subject.Name == "" {
			notes = append(notes, fmt.Sprintf("%s names no skill, so it cannot be matched "+
				"to anything on disk", path))
			continue
		}

		// The same digest approved twice is one fact recorded in two files — the legacy
		// name-keyed file beside a per-copy one, or a skill signed before and after a move —
		// not two approvals to report.
		duplicate := false
		for _, existing := range approvals[statement.Subject.Name] {
			if existing.Digest == statement.Subject.Digest {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}

		approvals[statement.Subject.Name] = append(approvals[statement.Subject.Name], Approval{
			Name:       statement.Subject.Name,
			Digest:     statement.Subject.Digest,
			ApprovedBy: statement.ApprovedBy,
			KeyID:      keyID,
		})
	}
	return approvals, notes, nil
}
