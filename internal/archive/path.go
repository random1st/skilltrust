package archive

import (
	"path"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

// zeroTime pins every member timestamp. Build time must never reach the payload.
var zeroTime = time.Unix(0, 0).UTC()

// canonicalMemberPath normalizes a relative path to the single form allowed in the archive.
//
// NFC normalization is load-bearing: macOS stores filenames decomposed and Linux composed,
// so without it the same commit produces two different digests on two developers' machines.
func canonicalMemberPath(relative string) (string, error) {
	normalized := norm.NFC.String(relative)
	if normalized == "" {
		return "", failf(KindPath, "archive paths cannot be empty")
	}
	if strings.ContainsRune(normalized, 0) {
		return "", failf(KindPath, "archive paths cannot contain NUL bytes")
	}
	if strings.Contains(normalized, `\`) {
		return "", failf(KindPath, "archive path %q must use POSIX separators only", relative)
	}
	if path.IsAbs(normalized) {
		return "", failf(KindPath, "archive path %q must be relative", relative)
	}

	segments := strings.Split(normalized, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", failf(KindPath,
				"archive path %q must not contain empty, '.' or '..' segments", relative)
		}
	}
	return strings.Join(segments, "/"), nil
}

func parentPaths(canonical string) []string {
	segments := strings.Split(canonical, "/")
	parents := make([]string, 0, len(segments)-1)
	for index := 1; index < len(segments); index++ {
		parents = append(parents, strings.Join(segments[:index], "/"))
	}
	return parents
}

// foldCase approximates the simple case folding that case-insensitive filesystems use.
// Full Unicode folding would be stricter than APFS or NTFS, and the point of this check is
// to catch paths that collide once the archive is written to such a filesystem.
func foldCase(value string) string { return strings.ToLower(value) }

const (
	entryDir  = "dir"
	entryFile = "file"
)

// pathRegistry rejects trees that cannot be extracted unambiguously: two members that
// differ only by case or Unicode form, a file where a directory is expected, or a
// directory nested under a regular file.
type pathRegistry struct {
	entries  map[string]string
	casefold map[string]string
}

func newPathRegistry() *pathRegistry {
	return &pathRegistry{entries: map[string]string{}, casefold: map[string]string{}}
}

func (r *pathRegistry) registerDir(relative string) error {
	canonical, err := canonicalMemberPath(relative)
	if err != nil {
		return err
	}
	return r.register(canonical, entryDir, true)
}

func (r *pathRegistry) registerFile(relative string) error {
	canonical, err := canonicalMemberPath(relative)
	if err != nil {
		return err
	}
	for _, parent := range parentPaths(canonical) {
		if err := r.register(parent, entryDir, true); err != nil {
			return err
		}
	}
	return r.register(canonical, entryFile, false)
}

func (r *pathRegistry) register(canonical, kind string, allowExistingDir bool) error {
	folded := foldCase(canonical)
	if existing, seen := r.casefold[folded]; seen && existing != canonical {
		return failf(KindCollision,
			"archive path %q collides with %q after NFC and case normalization",
			canonical, existing)
	}

	if existing, seen := r.entries[canonical]; seen {
		if kind == entryDir && allowExistingDir && existing == entryDir {
			return nil
		}
		return failf(KindCollision, "duplicate archive path %q is not allowed", canonical)
	}

	for _, parent := range parentPaths(canonical) {
		if r.entries[parent] == entryFile {
			return failf(KindCollision,
				"archive path %q descends from regular file %q", canonical, parent)
		}
	}

	if kind == entryFile {
		prefix := canonical + "/"
		for existing := range r.entries {
			if strings.HasPrefix(existing, prefix) {
				return failf(KindCollision,
					"regular file %q conflicts with descendant %q", canonical, existing)
			}
		}
	}

	r.entries[canonical] = kind
	r.casefold[folded] = canonical
	return nil
}
