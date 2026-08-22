// Package fleet reconciles the skills an organisation manages against what is on a machine.
//
// The boundary is the point of the package. A catalog names the skills it publishes, and
// only those are touched: everything else on the machine is the user's own work and is never
// restored, never removed, and never counted in a report. Both directions of getting that
// wrong are fatal to the product — staying quiet about a managed skill hides exactly the
// compromise this exists to catch, and touching an unmanaged one gets the tool uninstalled
// by lunchtime.
//
// Within the boundary the tool does restore, which is a stronger claim than the detection
// the rest of this project is careful to limit itself to. It is warranted there and nowhere
// else: the organisation owns those bytes, published them, and signed them, so putting them
// back is returning the machine to the state its owner declared rather than overriding
// anybody's decision.
package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/catalog"
)

// Action is what reconciling did to one managed skill.
type Action string

const (
	// ActionUnchanged means the bytes on disk are the bytes the catalog publishes.
	ActionUnchanged Action = "unchanged"
	// ActionInstalled means a managed skill was not present and was placed.
	ActionInstalled Action = "installed"
	// ActionUpdated means the catalog moved and the machine followed it.
	ActionUpdated Action = "updated"
	// ActionRolledBack means the copy on the machine had been changed and was restored.
	// This is the report the owner asked for by name.
	ActionRolledBack Action = "rolled back"
	// ActionRemoved means the published digest is revoked, so the skill was taken away.
	ActionRemoved Action = "removed"
	// ActionFailed means the skill could not be reconciled and the machine was left alone.
	ActionFailed Action = "failed"
)

// Change is one line of the report.
type Change struct {
	Name       string `json:"name"`
	Catalog    string `json:"catalog"`
	Action     Action `json:"action"`
	Was        string `json:"was,omitempty"`
	Now        string `json:"now,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Quarantine string `json:"quarantine,omitempty"`
}

// Needed reports whether a change is worth telling a person about. An unchanged skill is
// not news, and a reconciler that speaks every session is one people stop reading.
func (c Change) Needed() bool { return c.Action != ActionUnchanged }

// State is what this machine last applied from one catalog.
//
// Without it, "the catalog published new bytes" and "somebody edited the copy here" are the
// same observation — both are just a mismatch — and the report would have to guess. The
// difference is the entire difference between a routine update and an incident.
type State struct {
	Catalog  string            `json:"catalog"`
	Sequence int64             `json:"sequence"`
	Applied  map[string]string `json:"applied"`
}

// LoadState reads the applied state, treating absence as a machine that has never synced.
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{Applied: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("%s is not a readable state file: %w", path, err)
	}
	if state.Applied == nil {
		state.Applied = map[string]string{}
	}
	return &state, nil
}

// Save writes the state atomically.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(s, "", "  ")
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

// Options configures one reconciliation.
type Options struct {
	// SourceRoot is the verified catalog checkout the published bytes come from.
	SourceRoot string
	// InstallRoot is the skills directory the agent reads.
	InstallRoot string
	// QuarantineRoot is where a replaced local copy is kept. Restoring without keeping the
	// old bytes would destroy the evidence in the one case that is an incident.
	QuarantineRoot string
	// DryRun reports what would happen and changes nothing.
	DryRun bool
	// Now stamps quarantine directories.
	Now time.Time
}

// Reconcile brings the managed skills on a machine back to what the catalog publishes.
func Reconcile(snapshot *catalog.Snapshot, state *State, options Options) ([]Change, error) {
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}

	changes := make([]Change, 0, len(snapshot.Skills))
	for _, managed := range snapshot.Skills {
		changes = append(changes, reconcileOne(snapshot, state, managed, options))
	}

	// A skill this machine applied earlier that the catalog no longer publishes has been
	// withdrawn. It is removed for the same reason it was installed: the catalog decides
	// the managed set, and leaving an unpublished skill behind would let a withdrawn one
	// keep running forever.
	for name := range state.Applied {
		if _, still := snapshot.Publishes(name); still {
			continue
		}
		changes = append(changes, withdraw(state, name, snapshot, options))
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Name < changes[j].Name })
	return changes, nil
}

func reconcileOne(
	snapshot *catalog.Snapshot, state *State, managed catalog.Managed, options Options,
) Change {
	change := Change{Name: managed.Name, Catalog: snapshot.Name, Now: managed.Digest}
	destination := filepath.Join(options.InstallRoot, managed.Name)

	// Revocation is answered before anything is installed or restored. Publishing a digest
	// and revoking it are not contradictory — a catalog can be signed before the withdrawal
	// and the revocation list is the newer statement — so the refusal has to win.
	if entry, revoked := snapshot.IsRevoked(managed.Digest); revoked {
		change.Reason = entry.Reason
		return remove(change, destination, state, options)
	}

	source := managed.Path
	if source == "" {
		source = filepath.Join("skills", managed.Name)
	}
	sourceDir := filepath.Join(options.SourceRoot, filepath.FromSlash(source))

	published, err := archive.Build(sourceDir, archive.Limits{})
	if err != nil {
		change.Action, change.Reason = ActionFailed, err.Error()
		return change
	}
	// The catalog is signed, the repository is not. If they disagree, the bytes in the
	// checkout are not the bytes anybody approved, and installing them because they came
	// from the right URL is precisely the substitution the signature exists to stop.
	if published.Digest != managed.Digest {
		change.Action = ActionFailed
		change.Was = published.Digest
		change.Reason = "the catalog publishes " + managed.Digest +
			" but the repository holds " + published.Digest +
			"; refusing to install bytes the catalog does not name"
		return change
	}

	installed := digestOf(destination)
	change.Was = installed

	switch {
	case installed == managed.Digest:
		change.Action = ActionUnchanged
		return change
	case installed == "":
		change.Action = ActionInstalled
	case installed == state.Applied[managed.Name]:
		// The machine still holds exactly what it last applied, so the difference came from
		// the catalog. That is an ordinary release, not an incident.
		change.Action = ActionUpdated
	default:
		change.Action = ActionRolledBack
	}

	if options.DryRun {
		return change
	}
	if change.Action == ActionRolledBack {
		quarantined, err := quarantine(destination, options, managed.Name, snapshot.Name)
		if err != nil {
			change.Action, change.Reason = ActionFailed, err.Error()
			return change
		}
		change.Quarantine = quarantined
	}
	if err := install(published, destination); err != nil {
		change.Action, change.Reason = ActionFailed, err.Error()
		return change
	}
	state.Applied[managed.Name] = managed.Digest
	return change
}

func withdraw(state *State, name string, snapshot *catalog.Snapshot, options Options) Change {
	change := Change{
		Name: name, Catalog: snapshot.Name, Action: ActionRemoved,
		Was: state.Applied[name], Reason: "no longer published by this catalog",
	}
	return remove(change, filepath.Join(options.InstallRoot, name), state, options)
}

func remove(change Change, destination string, state *State, options Options) Change {
	change.Action, change.Now = ActionRemoved, ""
	if change.Was == "" {
		change.Was = digestOf(destination)
	}
	if _, err := os.Stat(destination); os.IsNotExist(err) {
		// Already gone. Reporting a removal that happened on some previous run would make
		// a revoked skill announce itself at every session for as long as the revocation
		// stands, which is how the one message that has to be read becomes the one people
		// have learned to scroll past.
		delete(state.Applied, change.Name)
		change.Action, change.Was = ActionUnchanged, ""
		return change
	}
	if options.DryRun {
		return change
	}
	// A removed skill is quarantined rather than deleted. The organisation withdrew it; the
	// person on the machine may still need to know what it said.
	if quarantined, err := quarantine(destination, options, change.Name, change.Catalog); err != nil {
		change.Action, change.Reason = ActionFailed, err.Error()
		return change
	} else {
		change.Quarantine = quarantined
	}
	delete(state.Applied, change.Name)
	return change
}

// quarantine moves a skill aside and returns where it went.
func quarantine(directory string, options Options, name, catalogName string) (string, error) {
	if options.QuarantineRoot == "" {
		return "", fmt.Errorf("no quarantine directory configured; refusing to replace %s "+
			"without keeping what was there", directory)
	}
	stamp := options.Now.Format("20060102T150405Z")
	base := filepath.Join(options.QuarantineRoot, catalogName, name+"-"+stamp)
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return "", err
	}

	// The stamp is only second-granular, so two rollbacks of the same skill within one
	// second collide. Never overwrite: the earlier directory is the earlier evidence, and a
	// quarantine that can clobber itself is worth less than no quarantine, because it looks
	// like it kept something. Suffix instead, and give up rather than guess after a while.
	target := base
	for attempt := 1; ; attempt++ {
		if _, err := os.Lstat(target); os.IsNotExist(err) {
			break
		}
		if attempt > 100 {
			return "", fmt.Errorf("cannot find an unused quarantine name beside %s", base)
		}
		target = fmt.Sprintf("%s-%d", base, attempt)
	}

	if err := os.Rename(directory, target); err != nil {
		return "", err
	}
	return target, nil
}

// install unpacks the published bytes, staging first so a failure cannot leave a partial
// skill under a name the agent will read and follow.
func install(published *archive.Archive, destination string) error {
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".skilltrust-staging-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	unpacked := filepath.Join(staging, "payload")
	if _, err := archive.ExtractVerified(
		published.Payload, unpacked, published.Digest, archive.Limits{}); err != nil {
		return err
	}
	if _, err := os.Stat(destination); err == nil {
		if err := os.RemoveAll(destination); err != nil {
			return err
		}
	}
	return os.Rename(unpacked, destination)
}

func digestOf(directory string) string {
	built, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		return ""
	}
	return built.Digest
}
