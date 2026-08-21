// Package archive builds the canonical bundle whose digest is the identity of a skill.
//
// Determinism is the whole point: the same source tree must produce byte-identical output
// on any machine, or signing a digest proves nothing. That is enforced by sorting members
// by canonical path, zeroing mtime/uid/gid, normalizing modes to two values, emitting no
// pax records, and normalizing paths to NFC so a macOS checkout and a Linux checkout agree.
//
// This is the only implementation of the canonical format. A second one, in another
// language, is where reproducibility dies silently.
package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/text/unicode/norm"
)

// Limits bound an untrusted source tree. They exist so that packaging a hostile directory
// fails loudly instead of exhausting the machine.
type Limits struct {
	MaxFiles        int
	MaxFileBytes    int64
	MaxTotalBytes   int64
	MaxArchiveBytes int64
}

// DefaultLimits mirrors the values the control plane packages with.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:        1024,
		MaxFileBytes:    8 << 20,
		MaxTotalBytes:   64 << 20,
		MaxArchiveBytes: 96 << 20,
	}
}

func (l Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = defaults.MaxFiles
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = defaults.MaxFileBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = defaults.MaxArchiveBytes
	}
	return l
}

// FileRecord is the builder-observed metadata for one packaged file.
type FileRecord struct {
	Path       string `json:"path"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
}

// Archive is a canonical bundle and its identity.
type Archive struct {
	Payload []byte       `json:"-"`
	Digest  string       `json:"digest"`
	Files   []FileRecord `json:"files"`
}

// Kind classifies a packaging failure so callers can map it to an exit code or a finding.
type Kind string

const (
	KindSource    Kind = "source"
	KindPath      Kind = "path"
	KindCollision Kind = "collision"
	KindEntryType Kind = "entry-type"
	KindLimit     Kind = "limit"
)

// Error is a packaging failure with a machine-readable kind.
type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string { return e.Message }

func failf(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

type collected struct {
	path       string
	content    []byte
	executable bool
}

// Build packages sourceDir into the canonical archive and returns its digest.
func Build(sourceDir string, limits Limits) (*Archive, error) {
	limits = limits.withDefaults()

	info, err := os.Lstat(sourceDir)
	if err != nil {
		return nil, failf(KindSource, "cannot read source directory %s: %v", sourceDir, err)
	}
	if !info.IsDir() {
		return nil, failf(KindSource, "source %s is not a directory", sourceDir)
	}

	files, err := collectFiles(sourceDir, limits)
	if err != nil {
		return nil, err
	}

	payload, err := encodeTar(files, limits)
	if err != nil {
		return nil, err
	}

	records := make([]FileRecord, 0, len(files))
	for _, file := range files {
		sum := sha256.Sum256(file.content)
		records = append(records, FileRecord{
			Path:       file.path,
			Digest:     "sha256:" + hex.EncodeToString(sum[:]),
			Size:       int64(len(file.content)),
			Executable: file.executable,
		})
	}

	sum := sha256.Sum256(payload)
	return &Archive{
		Payload: payload,
		Digest:  "sha256:" + hex.EncodeToString(sum[:]),
		Files:   records,
	}, nil
}

func collectFiles(sourceDir string, limits Limits) ([]collected, error) {
	registry := newPathRegistry()
	var files []collected
	var totalBytes int64

	var visit func(directory string) error
	visit = func(directory string) error {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return failf(KindSource, "cannot list %s: %v", directory, err)
		}
		sortEntries(entries)

		for _, entry := range entries {
			path := filepath.Join(directory, entry.Name())
			relative, err := relativePosix(sourceDir, path)
			if err != nil {
				return err
			}

			info, err := os.Lstat(path)
			if err != nil {
				return failf(KindSource, "cannot stat %s: %v", relative, err)
			}
			mode := info.Mode()

			switch {
			case mode&os.ModeSymlink != 0:
				return failf(KindEntryType,
					"source entry %q is a symlink; only regular files are allowed", relative)
			case mode.IsDir():
				if err := registry.registerDir(relative); err != nil {
					return err
				}
				if err := visit(path); err != nil {
					return err
				}
				continue
			case !mode.IsRegular():
				return failf(KindEntryType,
					"source entry %q is not a regular file; sockets, devices and FIFOs are denied",
					relative)
			}

			if links, known := hardLinkCount(info); known && links != 1 {
				return failf(KindEntryType,
					"source entry %q has %d hard links; hard-linked files are denied",
					relative, links)
			}

			if err := registry.registerFile(relative); err != nil {
				return err
			}

			content, err := readRegularFile(path, info)
			if err != nil {
				return err
			}

			size := int64(len(content))
			if size > limits.MaxFileBytes {
				return failf(KindLimit,
					"source file %q is %d bytes, above the %d-byte per-file limit",
					relative, size, limits.MaxFileBytes)
			}
			if totalBytes+size > limits.MaxTotalBytes {
				return failf(KindLimit,
					"source tree expands to %d bytes, above the %d-byte total limit",
					totalBytes+size, limits.MaxTotalBytes)
			}

			canonical, err := canonicalMemberPath(relative)
			if err != nil {
				return err
			}
			files = append(files, collected{
				path:       canonical,
				content:    content,
				executable: mode.Perm()&0o111 != 0,
			})

			if len(files) > limits.MaxFiles {
				return failf(KindLimit,
					"source tree contains %d files, above the %d-file limit",
					len(files), limits.MaxFiles)
			}
			totalBytes += size
		}
		return nil
	}

	if err := visit(sourceDir); err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

// sortEntries walks in a stable, locale-independent order. Output order is fixed by the
// final sort on canonical paths; this only makes error reporting deterministic.
func sortEntries(entries []os.DirEntry) {
	sort.Slice(entries, func(i, j int) bool {
		left, right := norm.NFC.String(entries[i].Name()), norm.NFC.String(entries[j].Name())
		leftFolded, rightFolded := foldCase(left), foldCase(right)
		if leftFolded != rightFolded {
			return leftFolded < rightFolded
		}
		return left < right
	})
}

// readRegularFile re-checks the file after opening it. Between Lstat and Open the path can
// be swapped for a symlink or another file, and packaging the wrong bytes under a reviewed
// digest is exactly the substitution this project exists to prevent.
func readRegularFile(path string, expected os.FileInfo) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, failf(KindSource, "source file %q could not be opened safely: %v", path, err)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, failf(KindSource, "source file %q could not be inspected: %v", path, err)
	}
	if !opened.Mode().IsRegular() {
		return nil, failf(KindEntryType, "source file %q is not a regular file", path)
	}
	if !os.SameFile(expected, opened) {
		return nil, failf(KindSource,
			"source file %q changed before it could be packaged; refusing to package a "+
				"tree that is being modified", path)
	}

	content, err := readAll(file)
	if err != nil {
		return nil, failf(KindSource, "source file %q could not be read: %v", path, err)
	}
	if int64(len(content)) != opened.Size() {
		return nil, failf(KindSource,
			"source file %q changed size while being read; refusing to package a tree that "+
				"is being modified", path)
	}
	return content, nil
}

func readAll(file *os.File) ([]byte, error) {
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(file); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// encodeTar writes the canonical payload. Every field that could vary between machines or
// runs is pinned to a constant.
func encodeTar(files []collected, limits Limits) ([]byte, error) {
	buffer := &bytes.Buffer{}
	writer := tar.NewWriter(buffer)

	for _, file := range files {
		mode := int64(0o644)
		if file.executable {
			mode = 0o755
		}
		header := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     file.path,
			Size:     int64(len(file.content)),
			Mode:     mode,
			Uid:      0,
			Gid:      0,
			Uname:    "",
			Gname:    "",
			ModTime:  zeroTime,
			Format:   tar.FormatPAX,
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, failf(KindPath, "cannot encode %q: %v", file.path, err)
		}
		if _, err := writer.Write(file.content); err != nil {
			return nil, failf(KindSource, "cannot write %q: %v", file.path, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, failf(KindSource, "cannot finalize the archive: %v", err)
	}

	payload := buffer.Bytes()
	if int64(len(payload)) > limits.MaxArchiveBytes {
		return nil, failf(KindLimit,
			"canonical archive is %d bytes, above the %d-byte limit",
			len(payload), limits.MaxArchiveBytes)
	}
	return payload, nil
}
