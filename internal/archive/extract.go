package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Extract writes a canonical archive into destination, which must be empty or absent.
//
// This is the only place untrusted bytes become files, so every guard that packaging
// applies is applied again here rather than assumed. An archive that verified somewhere
// else is still an archive whose contents this process has not inspected.
func Extract(payload []byte, destination string, limits Limits) ([]FileRecord, error) {
	limits = limits.withDefaults()

	if int64(len(payload)) > limits.MaxArchiveBytes {
		return nil, failf(KindLimit, "archive is %d bytes, above the %d-byte limit",
			len(payload), limits.MaxArchiveBytes)
	}

	root, err := filepath.Abs(destination)
	if err != nil {
		return nil, failf(KindSource, "cannot resolve %s: %v", destination, err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, failf(KindSource, "cannot create %s: %v", root, err)
	}

	registry := newPathRegistry()
	reader := tar.NewReader(bytes.NewReader(payload))
	var records []FileRecord
	var totalBytes int64

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, failf(KindSource, "archive is not readable: %v", err)
		}

		// Directories are implied by member paths; a canonical archive carries only
		// regular files, so anything else is a signal rather than a convenience.
		if header.Typeflag != tar.TypeReg {
			return nil, failf(KindEntryType,
				"archive entry %q has type %q; only regular files are allowed",
				header.Name, string(header.Typeflag))
		}

		path, err := canonicalMemberPath(header.Name)
		if err != nil {
			return nil, err
		}
		// Build never emits the reserved attestation, so an archive carrying one is
		// malformed by construction — and it is the specific malformation that would let a
		// bundle plant its own signature slot during extraction. Refusing here keeps the
		// envelope something a verifier reads from disk rather than something a payload
		// can supply about itself.
		if reserved, _ := matchesAttestationName(path); reserved {
			return nil, failf(KindEntryType,
				"archive member %q is the reserved attestation name; a canonical archive "+
					"never contains it", path)
		}
		if err := registry.registerFile(path); err != nil {
			return nil, err
		}

		if len(records) >= limits.MaxFiles {
			return nil, failf(KindLimit, "archive contains more than %d files", limits.MaxFiles)
		}
		if header.Size > limits.MaxFileBytes {
			return nil, failf(KindLimit,
				"archive entry %q is %d bytes, above the %d-byte per-file limit",
				path, header.Size, limits.MaxFileBytes)
		}

		// Read through a limited reader rather than trusting the declared size: a header
		// that lies about its length is the oldest trick an archive plays.
		content, err := io.ReadAll(io.LimitReader(reader, limits.MaxFileBytes+1))
		if err != nil {
			return nil, failf(KindSource, "cannot read archive entry %q: %v", path, err)
		}
		if int64(len(content)) > limits.MaxFileBytes {
			return nil, failf(KindLimit,
				"archive entry %q exceeds the %d-byte per-file limit while being read",
				path, limits.MaxFileBytes)
		}
		if int64(len(content)) != header.Size {
			return nil, failf(KindSource,
				"archive entry %q declares %d bytes but carries %d",
				path, header.Size, len(content))
		}

		totalBytes += int64(len(content))
		if totalBytes > limits.MaxTotalBytes {
			return nil, failf(KindLimit,
				"archive expands to more than %d bytes", limits.MaxTotalBytes)
		}

		executable := header.Mode&0o111 != 0
		target, err := resolveWithin(root, path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, failf(KindSource, "cannot create the parent of %q: %v", path, err)
		}
		if err := writeNewFile(target, content, executable); err != nil {
			return nil, err
		}

		sum := sha256.Sum256(content)
		records = append(records, FileRecord{
			Path:       path,
			Digest:     "sha256:" + hex.EncodeToString(sum[:]),
			Size:       int64(len(content)),
			Executable: executable,
		})
	}

	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

// ExtractVerified extracts and then re-packages the result, refusing to leave anything on
// disk unless the round trip reproduces the digest that was verified.
//
// Extraction is where a signature stops covering anything: from here on the bytes are
// files, and a mismatch means what landed is not what was approved.
func ExtractVerified(payload []byte, destination, expectedDigest string, limits Limits) ([]FileRecord, error) {
	sum := sha256.Sum256(payload)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, expectedDigest) {
		return nil, failf(KindSource,
			"archive digest %s does not match the expected %s", actual, expectedDigest)
	}

	records, err := Extract(payload, destination, limits)
	if err != nil {
		return nil, err
	}

	rebuilt, err := Build(destination, limits)
	if err != nil {
		return nil, err
	}
	if rebuilt.Digest != expectedDigest {
		return nil, failf(KindSource,
			"the extracted tree re-packages to %s, not %s; refusing to keep it",
			rebuilt.Digest, expectedDigest)
	}
	return records, nil
}

// resolveWithin rejects any path that would escape the destination once resolved. The
// canonical path check already forbids "..", so this is the belt to that braces: symlinked
// parents and case-insensitive filesystems can still move a target somewhere unexpected.
func resolveWithin(root, member string) (string, error) {
	target := filepath.Join(root, filepath.FromSlash(member))
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return "", failf(KindPath, "archive path %q does not resolve inside the destination", member)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", failf(KindPath, "archive path %q escapes the destination", member)
	}
	return target, nil
}

// writeNewFile refuses to replace anything. Extraction goes into a directory this process
// created, so an existing file means either a collision the registry missed or something
// else writing into the destination while it is being populated.
func writeNewFile(path string, content []byte, executable bool) error {
	mode := os.FileMode(0o644)
	if executable {
		mode = 0o755
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return failf(KindSource, "cannot create %s: %v", path, err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return failf(KindSource, "cannot write %s: %v", path, err)
	}
	// Chmod explicitly: O_CREATE applies the process umask, which would otherwise decide
	// whether a packaged executable stays executable.
	if err := file.Chmod(mode); err != nil {
		return failf(KindSource, "cannot set permissions on %s: %v", path, err)
	}
	return nil
}

// DigestOf is the identity of an already-packaged bundle.
func DigestOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
