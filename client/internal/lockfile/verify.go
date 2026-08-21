package lockfile

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/receipt"
)

// PinnedBy names the record an expected digest came from.
//
// There are two, and they are not interchangeable. A lock entry is a pin someone made
// deliberately over a whole tree; an install receipt is the digest skillctl installed a
// single skill under. Both are a recorded promise about bytes, so both are compared, but a
// report that does not say which one it used cannot be acted on: "re-approve it" and
// "reinstall it" are different instructions.
type PinnedBy string

const (
	// PinnedByNotarization is a signed attestation over the skill's digest.
	PinnedByNotarization PinnedBy = "notarization"
	// PinnedByLock is an entry in skills.lock.
	PinnedByLock PinnedBy = "lock"
	// PinnedByReceipt is an install record under .skilltrust.
	PinnedByReceipt PinnedBy = "receipt"
)

// Notarization is a signed approval of one skill's bytes, already verified against a pinned
// key by the time it reaches here.
type Notarization struct {
	Digest     string
	ApprovedBy string
	KeyID      string
}

// Records are everything that says what a skill's bytes should be, in the order they are
// trusted.
//
// The order is not a preference, it is a property. An attestation is the only one of the
// three that whoever edits a skill cannot also rewrite: the lock is a file in the tree they
// are editing, the receipt is a file in the tree they are editing, and both can simply be
// regenerated to match whatever they just wrote. Forging an attestation needs the signing
// key. So a signed approval outranks a local snapshot, and the consequence is deliberate:
// after you change your own skill, `lock` no longer re-approves it — `attest sign` does.
// That is the difference between a snapshot and a notarization, and it is the whole point.
type Records struct {
	Lock      *Lock
	LockPath  string
	Notarized map[string]Notarization
}

// Status is the verdict for one pinned skill.
type Status string

const (
	// StatusMatched means the tree on disk is byte-identical to what was pinned.
	StatusMatched Status = "matched"
	// StatusModified means the tree changed after it was pinned. This is the case the
	// whole tool exists for.
	StatusModified Status = "modified"
	// StatusAdded means a skill is present but was never pinned.
	StatusAdded Status = "added"
	// StatusRemoved means a pinned skill is gone from disk.
	StatusRemoved Status = "removed"
	// StatusUnreadable means the tree could not be packaged, so no claim can be made.
	// It is never treated as a match: an unverifiable skill is not a verified one.
	StatusUnreadable Status = "unreadable"
)

// Change describes one file inside a modified skill.
type Change struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}

// Result is the verdict for one skill, with the file-level detail behind it.
type Result struct {
	Name     string   `json:"name,omitempty"`
	Path     string   `json:"path"`
	Status   Status   `json:"status"`
	PinnedBy PinnedBy `json:"pinned_by,omitempty"`
	// ApprovedBy is set only for a notarized skill: the identity in the signed statement.
	// A digest says the bytes are the same ones; this says whose approval that was.
	ApprovedBy string   `json:"approved_by,omitempty"`
	Expected   string   `json:"expected,omitempty"`
	Actual     string   `json:"actual,omitempty"`
	Changes    []Change `json:"changes,omitempty"`
	Message    string   `json:"message,omitempty"`
}

// Report is the outcome of a verification run.
type Report struct {
	Root     string   `json:"root"`
	LockPath string   `json:"lock"`
	Results  []Result `json:"results"`
	// Unchecked lists what could not be examined at all. It is kept apart from the results
	// because "we checked and it is bad" and "we could not check" are different facts, and
	// the second must never be reported through the silence that means the first is absent.
	Unchecked []string `json:"unchecked,omitempty"`
}

// Drifted counts the skills that broke their pin. Added skills are excluded: adding a
// skill is ordinary work, while a pinned skill changing underneath you is not.
func (r *Report) Drifted() int {
	count := 0
	for _, result := range r.Results {
		switch result.Status {
		case StatusModified, StatusRemoved, StatusUnreadable:
			count++
		}
	}
	return count
}

// Unpinned counts skills present on disk but absent from the lock.
func (r *Report) Unpinned() int {
	count := 0
	for _, result := range r.Results {
		if result.Status == StatusAdded {
			count++
		}
	}
	return count
}

// Verify compares the tree under root against every record of what its bytes should be:
// signed attestations, the lock, and install receipts, in that order of precedence.
//
// Reading all three is not an extra feature, it is the removal of a contradiction. Verifying
// against the lock alone called a skill that skillctl had installed under a recorded digest
// "added" while sync called it drifted; and a tree of individually signed skills verified
// against nothing at all, because the one record carrying a signature was read by no command
// that ran routinely. An approval nothing consults is decoration.
func Verify(root string, records Records, options lint.Options) *Report {
	lock := records.Lock
	if lock == nil {
		lock = &Lock{Version: Version}
	}
	report := &Report{Root: root, LockPath: filepath.ToSlash(records.LockPath)}

	pinned := make(map[string]Entry, len(lock.Skills))
	pinnedNames := make(map[string]struct{}, len(lock.Skills))
	for _, entry := range lock.Skills {
		pinned[entry.Path] = entry
		if entry.Name != "" {
			pinnedNames[entry.Name] = struct{}{}
		}
	}

	// A receipt that cannot be read is not an absent one. Skipping it would report a
	// recorded skill as never recorded, which is the wrong direction to be wrong in, so the
	// failure is carried out to the caller instead of being swallowed here.
	receipts, err := receipt.LoadAll(root)
	if err != nil {
		report.Unchecked = append(report.Unchecked,
			fmt.Sprintf("install receipts under %s could not be read, so what they recorded "+
				"was not compared: %v", root, err))
	}
	installed := make(map[string]*receipt.Receipt, len(receipts))
	for _, record := range receipts {
		installed[record.Name] = record
	}

	directories, _ := lint.Discover(root, options)
	seenPaths := make(map[string]struct{}, len(directories))
	seenNames := make(map[string]struct{}, len(directories))
	results := make([]Result, 0, len(directories)+len(lock.Skills))

	for _, directory := range directories {
		path := relative(directory, root)
		seenPaths[path] = struct{}{}

		entry, isPinned := pinned[path]
		current, err := entryFor(directory, root)
		if err != nil {
			results = append(results, Result{
				Name: entry.Name, Path: path,
				Status: StatusUnreadable, Message: err.Error(),
			})
			continue
		}
		if current.Name != "" {
			seenNames[current.Name] = struct{}{}
		}

		result := Result{Name: current.Name, Path: path, Actual: current.Digest}
		record, isInstalled := installed[current.Name]
		approval, isNotarized := records.Notarized[current.Name]
		named := current.Name != ""

		switch {
		case isNotarized && named:
			result.PinnedBy, result.Expected = PinnedByNotarization, approval.Digest
			result.ApprovedBy = approval.ApprovedBy
		case isPinned:
			result.PinnedBy, result.Expected = PinnedByLock, entry.Digest
		case isInstalled && named:
			result.PinnedBy, result.Expected = PinnedByReceipt, record.Digest
		default:
			result.Status = StatusAdded
			results = append(results, result)
			continue
		}

		if result.Expected == current.Digest {
			result.Status = StatusMatched
			results = append(results, result)
			continue
		}

		result.Status = StatusModified

		// Only the lock stores per-file digests. It can still name the changed file for a
		// notarized skill, but only while it agrees with the signed digest — diffing against
		// a different baseline than the one that decided the verdict would name files that
		// have nothing to do with why this failed.
		switch {
		case result.PinnedBy == PinnedByLock:
			result.Changes = diffFiles(entry.Files, current.Files)
		case isPinned && entry.Digest == result.Expected:
			result.Changes = diffFiles(entry.Files, current.Files)
		case result.PinnedBy == PinnedByNotarization:
			// Reached when a lock exists but records different bytes than the signature —
			// which is exactly the case where the lock was regenerated over an edit. Naming
			// `lock` as the remedy here would recommend the action that hides the problem.
			result.Message = "the signature covers the skill's digest, not its files, and " +
				"the lock no longer agrees with it; re-approve with `skillctl setup` once " +
				"you know why it changed"
		default:
			result.Message = "the record holds the skill's digest but not its files; " +
				"run `skillctl lock` for file-level detail"
		}
		results = append(results, result)
	}

	for _, entry := range lock.Skills {
		if _, present := seenPaths[entry.Path]; present {
			continue
		}
		results = append(results, Result{
			Name: entry.Name, Path: entry.Path, Status: StatusRemoved,
			PinnedBy: PinnedByLock, Expected: entry.Digest,
		})
	}
	// Notarizations are deliberately not checked for absence, unlike the lock and receipts.
	// The approval store is machine-wide while a lock and a receipt live inside the tree
	// they describe, so "signed but not in this tree" is the ordinary case — the same skill
	// may be approved for a different directory, or simply not installed here — and reading
	// it as removal turned every unrelated tree into a report of dozens of missing skills.
	// Absence from one tree is only evidence when the record belonged to that tree.
	for _, record := range receipts {
		if _, present := seenNames[record.Name]; present {
			continue
		}
		if _, alsoPinned := pinnedNames[record.Name]; alsoPinned {
			continue // already reported as removed against the lock
		}
		// A receipt has no path: it records what was installed, not where it ended up.
		results = append(results, Result{
			Name: record.Name, Status: StatusRemoved,
			PinnedBy: PinnedByReceipt, Expected: record.Digest,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Path != results[j].Path {
			return results[i].Path < results[j].Path
		}
		return results[i].Name < results[j].Name
	})
	report.Results = results
	return report
}

// diffFiles names the files that moved, so the report gives a lead rather than an alarm.
func diffFiles(expected, actual []FileEntry) []Change {
	before := make(map[string]FileEntry, len(expected))
	for _, file := range expected {
		before[file.Path] = file
	}
	after := make(map[string]FileEntry, len(actual))
	for _, file := range actual {
		after[file.Path] = file
	}

	var changes []Change
	for _, file := range actual {
		previous, existed := before[file.Path]
		switch {
		case !existed:
			changes = append(changes, Change{Path: file.Path, Change: "added"})
		case previous.Digest != file.Digest:
			changes = append(changes, Change{Path: file.Path, Change: "modified"})
		case previous.Executable != file.Executable:
			// A file whose contents are unchanged but which became executable is a
			// meaningful change: it moves the skill out of the instruction-only tier.
			changes = append(changes, Change{Path: file.Path, Change: "permissions"})
		}
	}
	for _, file := range expected {
		if _, present := after[file.Path]; !present {
			changes = append(changes, Change{Path: file.Path, Change: "removed"})
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}
