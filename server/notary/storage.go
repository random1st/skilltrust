package notary

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/catalog"
)

// Storage is where a notary keeps what it accepted: countersigned catalogs, the
// rollback state guarding each one, and the events machines filed. The file
// implementation below is the default and the reference; a hosted deployment may keep
// the same records in an object store instead. Nothing about verification lives here —
// storage holds bytes the Service has already refused or accepted.
type Storage interface {
	// PutCatalog stores the countersigned envelope for a marketplace, atomically: a
	// reader must see the previous catalog or the new one, never a truncated middle.
	PutCatalog(org, marketplace string, body []byte) error
	// GetCatalog returns the stored envelope, or ErrAbsent.
	GetCatalog(org, marketplace string) ([]byte, error)
	// Marketplaces lists the names with a stored catalog, for the console. Unlistable
	// storage is an empty list: the console tolerates partial damage.
	Marketplaces(org string) []string
	// LoadState returns the highest accepted sequence; zero state when none recorded.
	LoadState(org, marketplace string) (*catalog.State, error)
	// SaveState records an accepted sequence via catalog.State.Save semantics — it
	// refuses to lower what it already recorded.
	SaveState(org, marketplace string, state *catalog.State, sequence int64, now time.Time) error
	// PutEvent stores one signed event envelope under its content-derived name;
	// storing the same name twice must stay idempotent.
	PutEvent(org, name string, body []byte) error
	// ListEvents returns every stored envelope, oldest name first. No events is nil,
	// not an error.
	ListEvents(org string) ([][]byte, error)
}

// Directory answers who is registered. The static implementation carries the config
// file's organisations; a hosted deployment resolves them from a database instead.
// Lookups happen on every request, so implementations cache accordingly.
type Directory interface {
	// LookupOrg follows the map idiom: the zero Org and false for an unknown name.
	LookupOrg(name string) (Org, bool)
}

// StaticDirectory is the Directory a fixed configuration provides.
type StaticDirectory map[string]Org

func (d StaticDirectory) LookupOrg(name string) (Org, bool) {
	org, known := d[name]
	return org, known
}

// FileStorage lays records out under root/orgs/<org>/<marketplace>/ exactly as notaryd
// always has, so an existing data directory keeps working unchanged.
type FileStorage struct {
	root string
}

func NewFileStorage(root string) *FileStorage {
	return &FileStorage{root: root}
}

func (f *FileStorage) catalogPath(org, marketplace string) string {
	return filepath.Join(f.root, "orgs", org, marketplace, "catalog.dsse.json")
}

func (f *FileStorage) PutCatalog(org, marketplace string, body []byte) error {
	path := f.catalogPath(org, marketplace)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeAtomically(path, body)
}

func (f *FileStorage) GetCatalog(org, marketplace string) ([]byte, error) {
	body, err := os.ReadFile(f.catalogPath(org, marketplace))
	if os.IsNotExist(err) {
		return nil, ErrAbsent
	}
	return body, err
}

func (f *FileStorage) Marketplaces(org string) []string {
	entries, err := os.ReadDir(filepath.Join(f.root, "orgs", org))
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "events" || !name.MatchString(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

func (f *FileStorage) statePath(org, marketplace string) string {
	return filepath.Join(f.root, "orgs", org, marketplace, "sequence.json")
}

func (f *FileStorage) LoadState(org, marketplace string) (*catalog.State, error) {
	return catalog.LoadState(f.statePath(org, marketplace))
}

func (f *FileStorage) SaveState(org, marketplace string, state *catalog.State, sequence int64, now time.Time) error {
	return state.Save(f.statePath(org, marketplace), sequence, now)
}

func (f *FileStorage) PutEvent(org, name string, body []byte) error {
	directory := filepath.Join(f.root, "orgs", org, "events")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return writeAtomically(filepath.Join(directory, name), body)
}

func (f *FileStorage) ListEvents(org string) ([][]byte, error) {
	directory := filepath.Join(f.root, "orgs", org, "events")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	events := make([][]byte, 0, len(names))
	for _, entryName := range names {
		body, err := os.ReadFile(filepath.Join(directory, entryName))
		if err != nil {
			return nil, err
		}
		events = append(events, body)
	}
	return events, nil
}
