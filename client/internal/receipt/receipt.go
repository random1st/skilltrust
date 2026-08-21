// Package receipt records what was installed, from where, and on whose approval.
//
// A lock says what the bytes should be. A receipt says how they got there: which source,
// which attestation, which key, at what time. Drift detection works without it, but the
// question an audit asks — who approved the thing that is on this machine — cannot be
// answered by a digest alone.
package receipt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Directory is where receipts live inside a skills tree. The leading dot keeps it out of
// the way of clients, which look for directories containing SKILL.md and ignore this one.
const Directory = ".skilltrust"

// Version is the receipt schema version.
const Version = 1

// Approval is the attestation a skill was installed under, when there was one.
type Approval struct {
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	KeyID string    `json:"key_id"`
	Notes string    `json:"notes,omitempty"`
}

// Receipt is the record written beside an installed skill.
type Receipt struct {
	Version     int       `json:"version"`
	Name        string    `json:"name"`
	Digest      string    `json:"digest"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
	// Approval is absent when a skill was installed without an attestation. That absence
	// is meaningful and is recorded as such rather than filled in with a placeholder: an
	// unapproved install must be distinguishable from an approved one forever after.
	Approval *Approval `json:"approval,omitempty"`
}

// Path returns where a skill's receipt belongs within a skills tree.
func Path(skillsRoot, name string) string {
	return filepath.Join(skillsRoot, Directory, name+".json")
}

// Save writes the receipt atomically.
func (r *Receipt) Save(path string) error {
	r.Version = Version
	r.InstalledAt = r.InstalledAt.UTC().Truncate(time.Second)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(append(body, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Load reads one receipt.
func Load(path string) (*Receipt, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record Receipt
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("%s is not a readable receipt: %w", path, err)
	}
	if record.Version != Version {
		return nil, fmt.Errorf("%s uses receipt version %d, this build understands %d",
			path, record.Version, Version)
	}
	return &record, nil
}

// LoadAll reads every receipt in a skills tree, sorted by name.
//
// A receipt that cannot be read is an error rather than a skipped entry: silently ignoring
// it would report a managed skill as unmanaged, which is the wrong direction to be wrong in.
func LoadAll(skillsRoot string) ([]*Receipt, error) {
	directory := filepath.Join(skillsRoot, Directory)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var records []*Receipt
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := Load(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records, nil
}

// Remove deletes a receipt, tolerating one that is already gone.
func Remove(skillsRoot, name string) error {
	err := os.Remove(Path(skillsRoot, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
