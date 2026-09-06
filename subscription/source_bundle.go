package subscription

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/random1st/skilltrust/internal/archive"
	"github.com/random1st/skilltrust/internal/lint"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
	"golang.org/x/text/unicode/norm"
)

// MaxSourceBytes bounds the compressed source response. The canonical archive's
// existing plugin limits independently bound its expanded size and file count.
const MaxSourceBytes = 4 << 20

// ValidateSourceRead checks whether omissions from a repository read affect its
// local plugin distribution. Omitted paths must be relative POSIX paths. Missing
// unrelated repository files and remote source contents do not prevent delivery.
// This check only reads the materialised manifest; it never writes to the source.
//
// A root plugin includes the whole repository, except the opaque root exclusions
// used by BuildSource. An omitted attestation is refused because an omission does
// not prove the regular-file type required by its canonical exclusion.
func ValidateSourceRead(repository string, omitted []string) error {
	for _, member := range omitted {
		if member == "" || member == "." || member == ".." || !utf8.ValidString(member) || strings.HasPrefix(member, "../") || path.IsAbs(member) ||
			strings.ContainsAny(member, "\\:\x00\r\n") || norm.NFC.String(member) != member || path.Clean(member) != member {
			return fmt.Errorf("omitted source path %q must be a canonical relative POSIX path", member)
		}
		// Only a native marketplace has a manifest to lose; a skills repository is
		// checked against its skill roots below like any other omission.
		if nativeSource(repository) && sourcePathsOverlap(member, marketplace.ManifestPath) {
			return fmt.Errorf("source read omitted the native marketplace manifest: %q", member)
		}
	}
	layout, err := readSourceLayout(repository, marketplace.PluginLimits().MaxFileBytes)
	if err != nil {
		return err
	}
	exclusions := append(append([]string{}, marketplace.ClientManagedRoots...), marketplace.SignatureFileName)
	for _, member := range omitted {
		for _, root := range layout.roots {
			if root == "." {
				first, _, _ := strings.Cut(member, "/")
				if sourceExcluded(first, exclusions) {
					continue
				}
			} else if !sourcePathsOverlap(member, root) {
				continue
			}
			return fmt.Errorf("source read omitted %q from local plugin source %q; a complete plugin read is required", member, root)
		}
	}
	return nil
}

// nativeSource reports whether a repository publishes through a native marketplace.
// The check is the directory, not the manifest file: a missing manifest inside an
// existing .claude-plugin is a broken native source, not a skills repository.
func nativeSource(repository string) bool {
	return sourceDirectory(repository, ".claude-plugin") == nil
}

func sourcePathsOverlap(left, right string) bool {
	left, right = strings.ToLower(left), strings.ToLower(right)
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

// BuildSource packages a marketplace's native manifest and every local plugin,
// including plugins without an approved version. Remote entries remain in the
// manifest; their contents and unrelated repository files are never included.
//
// A plugin whose source is "." explicitly publishes the repository root as its
// plugin content. That layout includes root files under the existing plugin
// identity rules, excluding Git, client-managed roots and root signatures. Use
// subdirectory sources when the rest of the repository must remain private.
// Overlapping sources are refused instead of changing either plugin's identity.
// The caller must supply an immutable source snapshot. Content omitted by Git's
// tracked-file view is refused instead of silently changing the plugin identity.
//
// The wire payload is gzip of the existing canonical tar format. Its identity is
// the SHA-256 of the uncompressed canonical archive, prefixed with "sha256:".
func BuildSource(repository string) (payload []byte, digest string, err error) {
	built, err := sourceArchive(repository, marketplace.PluginLimits())
	if err != nil {
		return nil, "", err
	}
	var buffer sourceWireBuffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(built.Payload); err != nil {
		_ = writer.Close()
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return buffer.Bytes(), built.Digest, nil
}

type sourceWireBuffer struct{ bytes.Buffer }

func (b *sourceWireBuffer) Write(body []byte) (int, error) {
	if len(body) > MaxSourceBytes-b.Len() {
		return 0, fmt.Errorf("marketplace source exceeds the %d-byte compressed limit", MaxSourceBytes)
	}
	return b.Buffer.Write(body)
}

// ExtractSource verifies a bounded source payload before making it visible at
// destination, which must not exist yet. All extraction and layout checks
// happen in an owned temporary directory. An error leaves destination unchanged.
func ExtractSource(payload []byte, destination, digest string) error {
	return extractSource(payload, destination, digest, marketplace.PluginLimits())
}

func extractSource(payload []byte, destination, digest string, limits archive.Limits) error {
	rawDigest, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if !strings.HasPrefix(digest, "sha256:") || digest != strings.ToLower(digest) || err != nil || len(rawDigest) != 32 {
		return fmt.Errorf("a canonical SHA-256 source digest is required")
	}
	if len(payload) > MaxSourceBytes {
		return fmt.Errorf("marketplace source exceeds the %d-byte compressed limit", MaxSourceBytes)
	}
	compressed := bytes.NewReader(payload)
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return fmt.Errorf("marketplace source is not readable gzip: %w", err)
	}
	reader.Multistream(false)
	expanded, readErr := io.ReadAll(io.LimitReader(reader, limits.MaxArchiveBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return fmt.Errorf("marketplace source is damaged: %w", readErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if int64(len(expanded)) > limits.MaxArchiveBytes {
		return fmt.Errorf("marketplace source exceeds the %d-byte expanded archive limit", limits.MaxArchiveBytes)
	}
	if compressed.Len() != 0 {
		return fmt.Errorf("marketplace source contains trailing data or multiple gzip streams")
	}
	if archive.DigestOf(expanded) != digest {
		return fmt.Errorf("marketplace source does not match its signed digest")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err := absentSourceDestination(destination); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(destination), ".axela-source-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	tree := filepath.Join(stage, "source")
	if _, err := archive.ExtractVerified(expanded, tree, digest, limits); err != nil {
		return err
	}
	// Canonical tar alone could carry unrelated repository files or a malformed
	// marketplace. Re-selecting its distribution proves this is exactly the
	// manifest and local trees that BuildSource is allowed to ship.
	rebuilt, err := sourceArchive(tree, limits)
	if err != nil {
		return err
	}
	if rebuilt.Digest != digest {
		return fmt.Errorf("marketplace source contains files outside its local plugin distribution")
	}
	if err := absentSourceDestination(destination); err != nil {
		return err
	}
	return os.Rename(tree, destination)
}

func absentSourceDestination(destination string) error {
	_, err := os.Lstat(destination)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("source destination already exists; choose a new directory and keep the existing files")
}

// sourceLayout describes what a repository publishes. A native marketplace carries
// a manifest that names its plugins; a skills repository carries no manifest at all,
// and manifest is nil for it.
type sourceLayout struct {
	manifest []byte
	mode     os.FileMode
	roots    []string
}

func (l *sourceLayout) native() bool { return l.manifest != nil }

func readSourceLayout(repository string, manifestLimit int64) (*sourceLayout, error) {
	if err := sourceDirectory(repository, "."); err != nil {
		return nil, err
	}
	if err := sourceDirectory(repository, ".claude-plugin"); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		// No native manifest: the other published shape, a repository of skills. It is
		// signed by `catalog publish` and installed by every loose-skills client, so
		// refusing to deliver it would sign what cannot be handed over.
		return looseSourceLayout(repository)
	}
	manifestPath := filepath.Join(repository, filepath.FromSlash(marketplace.ManifestPath))
	manifestBytes, mode, err := sourceManifest(manifestPath, manifestLimit)
	if err != nil {
		return nil, err
	}
	var manifest marketplace.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || !name.MatchString(manifest.Name) {
		return nil, fmt.Errorf("source needs a readable native marketplace with a valid name")
	}
	roots, err := localSourceRoots(&manifest)
	if err != nil {
		return nil, err
	}
	return &sourceLayout{manifest: manifestBytes, mode: mode, roots: roots}, nil
}

func sourceArchive(repository string, limits archive.Limits) (*archive.Archive, error) {
	layout, err := readSourceLayout(repository, limits.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	manifestBytes, mode, roots := layout.manifest, layout.mode, layout.roots
	stage, err := os.MkdirTemp("", ".axela-source-build-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	tree := filepath.Join(stage, "source")
	exclusions := append(append([]string{}, marketplace.ClientManagedRoots...), marketplace.SignatureFileName)
	fileCount, totalBytes := 1, int64(len(manifestBytes))
	if !layout.native() || (len(roots) == 1 && roots[0] == ".") {
		// A skills repository ships no manifest; a root plugin already contains it.
		fileCount, totalBytes = 0, 0
	}
	for _, relative := range roots {
		if err := sourceDirectory(repository, relative); err != nil {
			return nil, err
		}
		directory := filepath.Join(repository, filepath.FromSlash(relative))
		if err := boundSourceTree(directory, limits, exclusions); err != nil {
			return nil, err
		}
		built, err := archive.BuildExcluding(directory, limits, exclusions...)
		if err != nil {
			return nil, err
		}
		expected, _, err := marketplace.DigestPlugin(directory)
		if err != nil {
			return nil, err
		}
		if built.Digest != expected {
			return nil, fmt.Errorf("plugin source %q is not a clean published snapshot; remove untracked content before delivery", relative)
		}
		if len(built.Files) == 0 {
			return nil, fmt.Errorf("plugin source %q is empty; canonical source delivery needs a regular content file", relative)
		}
		for _, file := range built.Files {
			fileCount++
			totalBytes += file.Size
		}
		if fileCount > limits.MaxFiles || totalBytes > limits.MaxTotalBytes {
			return nil, fmt.Errorf("combined marketplace source exceeds the canonical archive limits")
		}
		if _, err := archive.ExtractVerified(built.Payload, filepath.Join(tree, filepath.FromSlash(relative)), built.Digest, limits); err != nil {
			return nil, err
		}
	}
	switch {
	case !layout.native():
	case len(roots) == 1 && roots[0] == ".":
		copied, _, err := sourceManifest(filepath.Join(tree, marketplace.ManifestPath), limits.MaxFileBytes)
		if err != nil || !bytes.Equal(copied, manifestBytes) {
			return nil, fmt.Errorf("the root plugin's marketplace manifest changed while packaging")
		}
	default:
		if err := os.MkdirAll(filepath.Join(tree, ".claude-plugin"), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(tree, marketplace.ManifestPath), manifestBytes, mode); err != nil {
			return nil, err
		}
		if err := os.Chmod(filepath.Join(tree, marketplace.ManifestPath), mode); err != nil {
			return nil, err
		}
	}
	built, err := archive.Build(tree, limits)
	if err != nil {
		return nil, err
	}
	if !layout.native() {
		// The staged tree holds exactly the discovered skills. Re-deriving the layout
		// from it on extraction is what proves that, so the only thing left to reject
		// here is an empty delivery.
		if len(built.Files) == 0 {
			return nil, fmt.Errorf("source has no skill files to deliver")
		}
		return built, nil
	}
	for _, file := range built.Files {
		if file.Path == marketplace.ManifestPath {
			return built, nil
		}
	}
	return nil, fmt.Errorf("source must contain the exact native path %s", marketplace.ManifestPath)
}

func sourceManifest(filename string, limit int64) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, 0, fmt.Errorf("marketplace manifest must be a bounded regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, 0, fmt.Errorf("marketplace manifest changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit || int64(len(body)) != opened.Size() {
		return nil, 0, fmt.Errorf("marketplace manifest is unreadable, oversized or changed while reading")
	}
	mode := os.FileMode(0o644)
	if info.Mode()&0o111 != 0 {
		mode = 0o755
	}
	// The manifest travels outside any subdirectory plugin. Apply the shared
	// builder's regular-file, hardlink and canonical-path guards to it too.
	checked, err := archive.BuildFiltered(filepath.Dir(filename), archive.Limits{
		MaxFiles: 1, MaxFileBytes: limit, MaxTotalBytes: limit, MaxArchiveBytes: limit + 2048,
	}, func(member string) bool { return member == filepath.Base(filename) })
	if err != nil {
		return nil, 0, err
	}
	if len(checked.Files) != 1 || checked.Files[0].Digest != archive.DigestOf(body) || checked.Files[0].Executable != (mode == 0o755) {
		return nil, 0, fmt.Errorf("marketplace manifest changed while packaging")
	}
	return body, mode, nil
}

func localSourceRoots(manifest *marketplace.Manifest) ([]string, error) {
	seenNames := map[string]bool{}
	var roots []string
	for _, entry := range manifest.Plugins {
		folded := strings.ToLower(norm.NFC.String(entry.Name))
		if !name.MatchString(entry.Name) || seenNames[folded] {
			return nil, fmt.Errorf("marketplace plugin names must be valid and unique: %q", entry.Name)
		}
		seenNames[folded] = true
		var source string
		if err := json.Unmarshal(entry.Source, &source); err != nil {
			if entry.SourceKind() == "unknown" {
				return nil, fmt.Errorf("plugin %q has an unsupported source", entry.Name)
			}
			continue // Keep the remote entry's original JSON, never fetch its contents.
		}
		relative := strings.TrimPrefix(source, "./")
		if source == "./" {
			relative = "."
		}
		if relative == "" || path.IsAbs(relative) || strings.ContainsAny(relative, "\\:\x00\r\n") || strings.Contains(relative, "..") || norm.NFC.String(relative) != relative || path.Clean(relative) != relative {
			return nil, fmt.Errorf("plugin %q needs a safe relative source path", entry.Name)
		}
		if relative != "." {
			for _, component := range strings.Split(relative, "/") {
				if component == ".." || component == "." || sourceExcluded(component, marketplace.ClientManagedRoots) {
					return nil, fmt.Errorf("plugin %q source cannot traverse or name client-managed data", entry.Name)
				}
			}
		}
		for _, previous := range roots {
			if previous == "." || relative == "." || sourcePathsOverlap(previous, relative) {
				return nil, fmt.Errorf("plugin sources %q and %q overlap; give each local plugin its own directory", previous, relative)
			}
		}
		// The native manifest is separately owned by the distribution.
		if relative != "." && (strings.EqualFold(relative, ".claude-plugin") || strings.HasPrefix(strings.ToLower(relative), ".claude-plugin/")) {
			return nil, fmt.Errorf("plugin source %q overlaps the native marketplace manifest", relative)
		}
		roots = append(roots, relative)
	}
	sort.Strings(roots)
	return roots, nil
}

// looseSourceLayout selects the skills a repository without a native manifest
// publishes, by the same rule that signed them: every SKILL.md discovered under
// skills/. Sharing lint.Discover is what keeps the index and the delivery from
// disagreeing about what the catalog contains — a repository is scanned from its
// root nowhere here, exactly as `catalog publish` refuses to sign one.
func looseSourceLayout(repository string) (*sourceLayout, error) {
	if err := sourceDirectory(repository, source.SkillsSubdirectory); err != nil {
		return nil, fmt.Errorf("source needs a native marketplace at %s or skills under %s/: %w",
			marketplace.ManifestPath, source.SkillsSubdirectory, err)
	}
	found, _ := lint.Discover(filepath.Join(repository, source.SkillsSubdirectory), lint.Options{})
	roots := make([]string, 0, len(found))
	for _, directory := range found {
		relative, err := filepath.Rel(repository, directory)
		if err != nil {
			return nil, err
		}
		relative = filepath.ToSlash(relative)
		if path.IsAbs(relative) || strings.Contains(relative, "..") || path.Clean(relative) != relative ||
			norm.NFC.String(relative) != relative {
			return nil, fmt.Errorf("skill source %q needs a safe relative path", relative)
		}
		roots = append(roots, relative)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("source has no skills under %s/ to deliver", source.SkillsSubdirectory)
	}
	sort.Strings(roots)
	// Discovery stops at the first SKILL.md on a branch, so nesting one skill inside
	// another cannot happen — assert it rather than trust it, because an overlap would
	// ship the same bytes under two identities.
	for index := 1; index < len(roots); index++ {
		if sourcePathsOverlap(roots[index-1], roots[index]) {
			return nil, fmt.Errorf("skill sources %q and %q overlap; give each skill its own directory",
				roots[index-1], roots[index])
		}
	}
	return &sourceLayout{roots: roots}, nil
}

func sourceDirectory(repository, relative string) error {
	current := repository
	components := []string{""}
	if relative != "." {
		components = append(components, strings.Split(relative, "/")...)
	}
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("local source %q must contain real directories, not symlinks or files", relative)
		}
	}
	return nil
}

func sourceExcluded(value string, exclusions []string) bool {
	for _, excluded := range exclusions {
		if strings.ToLower(norm.NFC.String(value)) == strings.ToLower(excluded) {
			return true
		}
	}
	return false
}

// Check declared sizes before the shared builder reads file contents. Nested Git
// data cannot be silently removed: it is part of the outer plugin's identity, so
// this layout must be repaired before it can be distributed.
func boundSourceTree(directory string, limits archive.Limits, exclusions []string) error {
	var count int
	var total int64
	return filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == directory {
			return nil
		}
		if filepath.Dir(filename) == directory && sourceExcluded(entry.Name(), exclusions) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(norm.NFC.String(entry.Name()), ".git") {
			return fmt.Errorf("nested Git data cannot be delivered as plugin content: %q", filename)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("plugin content must use regular files, not symlinks or special files: %q", filename)
		}
		count++
		total += info.Size()
		if count > limits.MaxFiles || info.Size() > limits.MaxFileBytes || total > limits.MaxTotalBytes {
			return fmt.Errorf("plugin source exceeds the canonical archive limits")
		}
		return nil
	})
}
