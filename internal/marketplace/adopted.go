package marketplace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Adoptions are the changes the person at this machine made on purpose.
//
// Editing a skill to fit your own setup is the most ordinary thing anyone does with one, and
// until this existed the checker treated it exactly like tampering: the edit went to
// quarantine and the published bytes came back, every session, without a word. A tool that
// silently undoes your work each morning gets uninstalled, and an uninstalled checker
// protects nothing — so refusing to model local customisation was not the cautious choice,
// it was the one that lost the protection entirely.
//
// What is recorded is deliberately narrow. An adoption names the exact local bytes and the
// exact published digest they were adopted away from. It is not "stop checking this plugin":
// if the file changes again, or the publisher ships a new version, the adoption stops
// applying and the difference goes back to being something a person has to answer for.
type Adoptions struct {
	Entries []Adoption `json:"adopted"`
}

// Adoption is one plugin this machine deliberately runs modified.
type Adoption struct {
	Marketplace string `json:"marketplace"`
	Plugin      string `json:"plugin"`
	// From is the published digest this diverged from, and Local is what is on disk now.
	// Both are needed: From notices the publisher moving on, Local notices anyone else
	// touching the file afterwards. Keeping only one would silently cover the other case.
	From  string    `json:"from"`
	Local string    `json:"local"`
	Since time.Time `json:"since"`
	// Version is the release the adopted bytes belong to. Without it, a record left behind
	// by an upstream version bump cannot even be described: the reconciler checks the
	// version the catalog signs now, never digests the old install, and the record sits in
	// `adopt --list` looking alive. Empty on records written before this field existed.
	Version string `json:"version,omitempty"`
	// Reason is required. An adoption with no reason cannot be told apart from a mistake,
	// and a year later cannot be told apart from a decision nobody remembers making.
	Reason string `json:"reason"`
}

// Find returns the adoption for a plugin, if this machine has one.
func (a Adoptions) Find(marketplace, plugin string) (Adoption, bool) {
	for _, entry := range a.Entries {
		if entry.Marketplace == marketplace && entry.Plugin == plugin {
			return entry, true
		}
	}
	return Adoption{}, false
}

// Record adds or replaces an adoption and returns the updated set.
func (a Adoptions) Record(entry Adoption) Adoptions {
	kept := make([]Adoption, 0, len(a.Entries)+1)
	for _, existing := range a.Entries {
		if existing.Marketplace != entry.Marketplace || existing.Plugin != entry.Plugin {
			kept = append(kept, existing)
		}
	}
	kept = append(kept, entry)
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Marketplace != kept[j].Marketplace {
			return kept[i].Marketplace < kept[j].Marketplace
		}
		return kept[i].Plugin < kept[j].Plugin
	})
	return Adoptions{Entries: kept}
}

// Forget removes an adoption, so the next check restores the published bytes.
func (a Adoptions) Forget(marketplace, plugin string) (Adoptions, bool) {
	kept := make([]Adoption, 0, len(a.Entries))
	for _, existing := range a.Entries {
		if existing.Marketplace == marketplace && existing.Plugin == plugin {
			continue
		}
		kept = append(kept, existing)
	}
	return Adoptions{Entries: kept}, len(kept) != len(a.Entries)
}

// LoadAdoptions reads the machine's adoptions. A missing file is an empty set, not an error:
// a machine that has adopted nothing is the normal case.
func LoadAdoptions(path string) (Adoptions, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Adoptions{}, nil
	}
	if err != nil {
		return Adoptions{}, err
	}
	var adoptions Adoptions
	if err := json.Unmarshal(body, &adoptions); err != nil {
		// An unreadable file adopts nothing. The failure direction matters: the alternative
		// is a corrupt file quietly meaning "accept every difference on this machine".
		return Adoptions{}, fmt.Errorf("%s is not readable, so nothing is adopted: %w", path, err)
	}
	var usable []Adoption
	for _, entry := range adoptions.Entries {
		// An entry missing its bytes or its reason cannot do the job the record exists for,
		// so it is dropped rather than half-honoured.
		if entry.Plugin == "" || entry.Local == "" || strings.TrimSpace(entry.Reason) == "" {
			continue
		}
		usable = append(usable, entry)
	}
	return Adoptions{Entries: usable}, nil
}

// SaveAdoptions writes the set back.
func SaveAdoptions(path string, adoptions Adoptions) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(adoptions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}
