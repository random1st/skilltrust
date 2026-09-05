package notary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/report"
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
	// SaveCheck stores the latest current-check receipt per signer and scope, returning the
	// canonical receipt for that row. Replaying the same envelope returns the original
	// receipt; a lower or conflicting sequence is refused.
	SaveCheck(org string, record CheckRecord) (Receipt, error)
	// ListChecks returns the bounded current-check rows for one organisation.
	ListChecks(org string) ([]CheckRecord, error)
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

// RegisteredMachines is absent from a static config unless a caller wraps it with a
// directory that carries named machine records, so the file-backed default reports none.
func (d StaticDirectory) RegisteredMachines(string) ([]Machine, error) {
	return nil, nil
}

// FileStorage lays records out under root/orgs/<org>/<marketplace>/ exactly as notaryd
// always has, so an existing data directory keeps working unchanged.
type FileStorage struct {
	root string
	mu   sync.Mutex
}

// Receipt is the immutable server-stamped evidence that a current check was admitted.
type Receipt struct {
	Signer     string    `json:"signer"`
	AcceptedAt time.Time `json:"accepted_at"`
	Digest     string    `json:"digest"`
}

// CheckRecord is one current-state row: the machine's signed result plus the server's
// receipt about which signer and accepted envelope it came from.
type CheckRecord struct {
	Result   report.CheckResult `json:"result"`
	Receipt  Receipt            `json:"receipt"`
	Envelope []byte             `json:"envelope,omitempty"`
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

func (f *FileStorage) checksDir(org string) string {
	return filepath.Join(f.root, "checks", org)
}

func (f *FileStorage) checkPath(org, signer, scope string) string {
	sum := sha256.Sum256([]byte(signer + "\x00" + scope))
	return filepath.Join(f.checksDir(org), hex.EncodeToString(sum[:])+".json")
}

func (f *FileStorage) SaveCheck(org string, record CheckRecord) (Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if record.Result.Scope == "" {
		return Receipt{}, fmt.Errorf("check record needs a scope")
	}
	if record.Receipt.Signer == "" {
		return Receipt{}, fmt.Errorf("check record needs a signer")
	}
	if record.Receipt.AcceptedAt.IsZero() {
		return Receipt{}, fmt.Errorf("check record needs an accepted_at time")
	}
	if record.Receipt.Digest == "" {
		return Receipt{}, fmt.Errorf("check record needs a digest")
	}
	if err := os.MkdirAll(f.checksDir(org), 0o700); err != nil {
		return Receipt{}, err
	}
	path := f.checkPath(org, record.Receipt.Signer, record.Result.Scope)
	current, err := f.readCheck(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return Receipt{}, err
	case current.Receipt.Digest == record.Receipt.Digest:
		return current.Receipt, nil
	case record.Result.Sequence <= current.Result.Sequence:
		return Receipt{}, fmt.Errorf("%w: current check sequence did not move forward", ErrRefused)
	}
	body, err := json.Marshal(record)
	if err != nil {
		return Receipt{}, err
	}
	if err := writeAtomically(path, body); err != nil {
		return Receipt{}, err
	}
	return record.Receipt, nil
}

func (f *FileStorage) ListChecks(org string) ([]CheckRecord, error) {
	entries, err := os.ReadDir(f.checksDir(org))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	checks := make([]CheckRecord, 0, len(names))
	for _, name := range names {
		record, err := f.readCheck(filepath.Join(f.checksDir(org), name))
		if err != nil {
			return nil, err
		}
		checks = append(checks, record)
	}
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].Result.Machine != checks[j].Result.Machine {
			return checks[i].Result.Machine < checks[j].Result.Machine
		}
		if checks[i].Result.Scope != checks[j].Result.Scope {
			return checks[i].Result.Scope < checks[j].Result.Scope
		}
		return checks[i].Receipt.Signer < checks[j].Receipt.Signer
	})
	return checks, nil
}

func (f *FileStorage) readCheck(path string) (CheckRecord, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return CheckRecord{}, err
	}
	var record CheckRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return CheckRecord{}, err
	}
	return record, nil
}
