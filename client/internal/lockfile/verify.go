package lockfile

import (
	"path/filepath"
	"sort"

	"github.com/random1st/skilltrust/client/internal/lint"
)

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
	Expected string   `json:"expected,omitempty"`
	Actual   string   `json:"actual,omitempty"`
	Changes  []Change `json:"changes,omitempty"`
	Message  string   `json:"message,omitempty"`
}

// Report is the outcome of a verification run.
type Report struct {
	Root     string   `json:"root"`
	LockPath string   `json:"lock"`
	Results  []Result `json:"results"`
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

// Verify compares the tree under root against the lock.
func Verify(root, lockPath string, lock *Lock, options lint.Options) *Report {
	pinned := make(map[string]Entry, len(lock.Skills))
	for _, entry := range lock.Skills {
		pinned[entry.Path] = entry
	}

	directories, _ := lint.Discover(root, options)
	seen := make(map[string]struct{}, len(directories))
	results := make([]Result, 0, len(directories)+len(lock.Skills))

	for _, directory := range directories {
		path := relative(directory, root)
		seen[path] = struct{}{}

		entry, isPinned := pinned[path]
		current, err := entryFor(directory, root)
		if err != nil {
			results = append(results, Result{
				Name: entry.Name, Path: path,
				Status: StatusUnreadable, Message: err.Error(),
			})
			continue
		}
		if !isPinned {
			results = append(results, Result{
				Name: current.Name, Path: path, Status: StatusAdded, Actual: current.Digest,
			})
			continue
		}
		if entry.Digest == current.Digest {
			results = append(results, Result{
				Name: current.Name, Path: path, Status: StatusMatched, Actual: current.Digest,
			})
			continue
		}
		results = append(results, Result{
			Name: current.Name, Path: path, Status: StatusModified,
			Expected: entry.Digest, Actual: current.Digest,
			Changes: diffFiles(entry.Files, current.Files),
		})
	}

	for _, entry := range lock.Skills {
		if _, present := seen[entry.Path]; present {
			continue
		}
		results = append(results, Result{
			Name: entry.Name, Path: entry.Path, Status: StatusRemoved, Expected: entry.Digest,
		})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return &Report{Root: root, LockPath: filepath.ToSlash(lockPath), Results: results}
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
