package attest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// StoreDirectory is where a machine keeps the attestations it has been given, one file per
// skill. Keeping them outside the skills tree is deliberate: an approval that lives beside
// the thing it approves is deleted by whatever deletes that thing.
const StoreDirectory = "attestations"

// StorePath is the conventional file for one skill's attestation inside a store.
func StorePath(directory, name string) string {
	return filepath.Join(directory, name+".att.json")
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
// the pinned keys, indexed by the skill they name.
//
// Failures are returned as notes rather than dropped. An attestation that does not verify is
// the single most interesting file in the store — it is either corrupt or forged — and a
// loader that silently skips it turns the strongest available signal into an absence, which
// reads as "this skill was never approved" and is acted on as though nobody had ever signed
// anything. A missing directory is different, and is not a failure: it means no approvals
// have been given yet.
func LoadStore(directory string, trusted *TrustedKeys) (map[string]Approval, []string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	approvals := map[string]Approval{}
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

		// Two signed approvals for one name is not a merge to resolve quietly. Keeping the
		// first and reporting the rest means the choice is visible instead of depending on
		// directory order.
		if existing, clash := approvals[statement.Subject.Name]; clash &&
			existing.Digest != statement.Subject.Digest {
			notes = append(notes, fmt.Sprintf(
				"%s approves a different digest for %q than an earlier attestation; the "+
					"earlier one was used", path, statement.Subject.Name))
			continue
		}

		approvals[statement.Subject.Name] = Approval{
			Name:       statement.Subject.Name,
			Digest:     statement.Subject.Digest,
			ApprovedBy: statement.ApprovedBy,
			KeyID:      keyID,
		}
	}
	return approvals, notes, nil
}
