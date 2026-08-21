// Package lockfile pins a tree of skills by digest and detects drift against that pin.
//
// This is the answer to a narrower and more immediate question than third-party trust:
// have my own skills changed since I approved them? An agent that can write files can
// edit its own SKILL.md to make an injected instruction survive the session, and nothing
// else notices, because the edit is made by a legitimate process with legitimate
// permissions and looks like ordinary work.
package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/skillmd"
)

// FileName is the conventional lock name, committed alongside the skills it pins.
const FileName = "skills.lock"

// Version is the lock format version. It changes only when the file layout changes, never
// when the tool is released, so a lock does not churn between versions of skillctl.
const Version = 1

// FileEntry pins one file inside a skill.
//
// Per-file digests are stored deliberately. Without them verify can only report that a
// skill changed, and "something changed" is an alert nobody acts on. With them it reports
// which file moved, which is the difference between noise and a lead. They also matter
// where git cannot help: a tree under ~/.claude/skills is usually not a repository at all.
type FileEntry struct {
	Path       string `json:"path"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable,omitempty"`
}

// Entry pins one skill directory.
type Entry struct {
	Name   string      `json:"name,omitempty"`
	Path   string      `json:"path"`
	Digest string      `json:"digest"`
	Files  []FileEntry `json:"files"`
}

// Lock is the whole pinned set.
type Lock struct {
	Version int     `json:"version"`
	Skills  []Entry `json:"skills"`
}

// Build scans root and pins every skill it finds.
func Build(root string, options lint.Options) (*Lock, error) {
	directories, _ := lint.Discover(root, options)

	skills := make([]Entry, 0, len(directories))
	for _, directory := range directories {
		entry, err := entryFor(directory, root)
		if err != nil {
			return nil, err
		}
		skills = append(skills, entry)
	}
	sort.Slice(skills, func(i, j int) bool { return skills[i].Path < skills[j].Path })

	return &Lock{Version: Version, Skills: skills}, nil
}

func entryFor(directory, root string) (Entry, error) {
	result, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", relative(directory, root), err)
	}

	files := make([]FileEntry, 0, len(result.Files))
	for _, file := range result.Files {
		files = append(files, FileEntry{
			Path:       file.Path,
			Digest:     file.Digest,
			Size:       file.Size,
			Executable: file.Executable,
		})
	}

	name, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
	return Entry{
		Name:   name,
		Path:   relative(directory, root),
		Digest: result.Digest,
		Files:  files,
	}, nil
}

// Load reads a lock. A missing lock is reported as such so callers can tell "not pinned
// yet" apart from "pinned and broken"; conflating the two turns a first run into a
// failure and a tampered tree into a shrug.
func Load(path string) (*Lock, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock Lock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("%s is not a readable lock: %w", path, err)
	}
	if lock.Version != Version {
		return nil, fmt.Errorf("%s has lock format version %d, this build understands %d",
			path, lock.Version, Version)
	}
	return &lock, nil
}

// Save writes the lock atomically, so an interrupted run cannot leave a truncated pin that
// would later read as "everything matches".
func (l *Lock) Save(path string) error {
	encoded, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(encoded); err != nil {
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

func relative(path, root string) string {
	result, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(result)
}
