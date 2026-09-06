package subscription

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/internal/archive"
	"github.com/random1st/skilltrust/internal/marketplace"
)

func sourceFile(t *testing.T, root, member, body string, mode os.FileMode) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(member))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, mode); err != nil {
		t.Fatal(err)
	}
}

func sourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sourceFile(t, root, marketplace.ManifestPath, `{
  "name": "private-skills",
  "owner": {"name": "Example"},
  "metadata": {"description": "native fields survive byte for byte"},
  "plugins": [
    {"name": "signed", "source": "./plugins/signed", "version": "1.0.0"},
    {"name": "unapproved", "source": "./plugins/unapproved"},
    {"name": "remote", "source": {"source": "github", "repo": "example/elsewhere"}}
  ]
}
`, 0o644)
	sourceFile(t, root, "plugins/signed/SKILL.md", "# Signed instructions\n", 0o644)
	sourceFile(t, root, "plugins/signed/scripts/run.sh", "#!/bin/sh\nprintf 'hello'\n", 0o755)
	sourceFile(t, root, "plugins/signed/.hidden-note", "hidden plugin content\n", 0o644)
	sourceFile(t, root, "plugins/unapproved/SKILL.md", "# Unapproved sibling\n", 0o644)
	sourceFile(t, root, "plugins/remote/SECRET.txt", "REMOTE-CONTENT-MUST-NOT-TRAVEL", 0o644)
	sourceFile(t, root, "company-private.txt", "UNRELATED-ROOT-CONTENT-MUST-NOT-TRAVEL", 0o600)
	sourceFile(t, root, ".git/source-fixture", "GIT-DATA-MUST-NOT-TRAVEL", 0o600)
	return root
}

func sourceSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(relative)] = fmt.Sprintf("%o:%s", info.Mode().Perm(), body)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func sourceCoverage(t *testing.T, root string) *marketplace.Coverage {
	t.Helper()
	manifest, err := marketplace.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := marketplace.Plan(root, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return coverage
}

func gunzipSource(t *testing.T, payload []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return body
}

func gzipSource(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestValidateSourceReadIgnoresUnrelatedOmissionsAndPreservesCoverage(t *testing.T) {
	root := sourceFixture(t)
	before := sourceSnapshot(t, root)
	coverage := sourceCoverage(t, root)
	omitted := []string{
		"unrelated-large-model.bin", "plugins/remote/large.bin", "plugins/signed-neighbor/tool.bin",
		"elsewhere/plugins/signed/tool.bin", ".git/config", "downloads/model..bin", "other/has ' spaces.bin",
	}
	if err := ValidateSourceRead(root, omitted); err != nil {
		t.Fatalf("unrelated omissions blocked a complete local plugin distribution: %v", err)
	}
	if after := sourceSnapshot(t, root); !reflect.DeepEqual(after, before) {
		t.Fatal("source read validation wrote to its source")
	}
	payload, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "validated-distribution")
	if err := ExtractSource(payload, destination, digest); err != nil {
		t.Fatal(err)
	}
	if after := sourceCoverage(t, destination); !reflect.DeepEqual(after, coverage) ||
		len(after.Signed) != 1 || len(after.Unversioned) != 1 || len(after.Remote["github"]) != 1 {
		t.Fatalf("ignoring unrelated omissions changed actual native coverage: %+v", after)
	}
}

func TestValidateSourceReadRefusesOmittedLocalPluginContent(t *testing.T) {
	root := sourceFixture(t)
	before := sourceSnapshot(t, root)
	for _, member := range []string{
		"plugins/signed/large.bin", "plugins/unapproved/large.bin", "plugins/signed", "plugins",
		"PLUGINS/SIGNED/large.bin", "plugins/signed/.git/config", "plugins/signed/node_modules/runtime.bin",
	} {
		t.Run(member, func(t *testing.T) {
			if err := ValidateSourceRead(root, []string{member}); err == nil || !strings.Contains(err.Error(), "complete plugin read") {
				t.Fatalf("omitted selected local content %q was not refused: %v", member, err)
			}
		})
	}
	if after := sourceSnapshot(t, root); !reflect.DeepEqual(after, before) {
		t.Fatal("refusing an incomplete read changed the source")
	}
}

func TestValidateSourceReadRootPluginUsesOnlyOpaqueRootExclusions(t *testing.T) {
	root := t.TempDir()
	sourceFile(t, root, marketplace.ManifestPath, `{"name":"root-market","plugins":[{"name":"root-plugin","source":".","version":"1.0.0"}]}`, 0o644)
	sourceFile(t, root, "SKILL.md", "# Root plugin\n", 0o644)
	if err := ValidateSourceRead(root, []string{
		".git/config", ".GIT/missing-link", ".in_use/123", "node_modules/runtime.bin",
		"NODE_MODULES/runtime.bin", marketplace.SignatureFileName, "CATALOG.DSSE.JSON/missing-link",
	}); err != nil {
		t.Fatalf("opaque root exclusions blocked source delivery: %v", err)
	}
	for _, member := range []string{
		"large.bin", "scripts/runtime.bin", ".claude-plugin/plugin.json", archive.AttestationFileName,
		"attestation.dsse.json", "nested/.git/config", "nested/node_modules/runtime.bin",
		"node_modules-extra/runtime.bin", "catalog.dsse.json.bak",
	} {
		t.Run(member, func(t *testing.T) {
			if err := ValidateSourceRead(root, []string{member}); err == nil {
				t.Fatalf("root source delivered after omitting potentially signed content %q", member)
			}
		})
	}
}

func TestValidateSourceReadRefusesOmittedOrUnreadableManifest(t *testing.T) {
	root := sourceFixture(t)
	for _, member := range []string{
		marketplace.ManifestPath, ".claude-plugin", ".CLAUDE-PLUGIN/MARKETPLACE.JSON",
		marketplace.ManifestPath + "/missing-link",
	} {
		if err := ValidateSourceRead(root, []string{member}); err == nil || !strings.Contains(err.Error(), "native marketplace manifest") {
			t.Fatalf("omitted native manifest %q was not refused: %v", member, err)
		}
	}
	if err := os.Remove(filepath.Join(root, marketplace.ManifestPath)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceRead(root, nil); err == nil {
		t.Fatal("an unreadable native manifest was accepted without a reported omission")
	}
}

func TestValidateSourceReadRefusesMalformedOmissionPaths(t *testing.T) {
	root := sourceFixture(t)
	for _, member := range []string{
		"", ".", "..", "../outside", "/absolute", "./unrelated", "a/../unrelated", "a//unrelated", "unrelated/",
		"C:/unrelated", "a\\unrelated", "a\x00b", "a\r\nb", "a\xffb", "cafe\u0301.bin", ".git/../unrelated",
	} {
		t.Run(member, func(t *testing.T) {
			if err := ValidateSourceRead(root, []string{member}); err == nil || !strings.Contains(err.Error(), "relative POSIX path") {
				t.Fatalf("malformed omission path %q was not refused: %v", member, err)
			}
		})
	}
}

func TestValidateSourceReadUsesTheCanonicalNativeLayoutContract(t *testing.T) {
	for _, manifest := range []string{
		`not json`,
		`{"name":"not/a/name","plugins":[]}`,
		`{"name":"market","plugins":[{"name":"plugin","source":"../outside"}]}`,
		`{"name":"market","plugins":[{"name":"one","source":"plugins/one"},{"name":"two","source":"plugins/one/inner"}]}`,
		`{"name":"market","plugins":[{"name":"plugin","source":{"repo":"missing/source-kind"}}]}`,
	} {
		root := t.TempDir()
		sourceFile(t, root, marketplace.ManifestPath, manifest, 0o644)
		if err := ValidateSourceRead(root, nil); err == nil {
			t.Fatalf("invalid native layout was accepted: %s", manifest)
		}
	}
}

func TestSourceBundleRoundTripKeepsCoverageAndOnlyLocalPluginContent(t *testing.T) {
	root := sourceFixture(t)
	before := sourceSnapshot(t, root)
	coverage := sourceCoverage(t, root)
	if len(coverage.Signed) != 1 || len(coverage.Unversioned) != 1 || len(coverage.Remote["github"]) != 1 {
		t.Fatalf("fixture lost its three coverage classes: %+v", coverage)
	}
	payload, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	canonical := gunzipSource(t, payload)
	if archive.DigestOf(canonical) != digest || len(payload) > MaxSourceBytes {
		t.Fatal("wire payload does not carry its canonical archive identity")
	}
	for _, secret := range []string{"UNRELATED-ROOT-CONTENT", "REMOTE-CONTENT", "GIT-DATA"} {
		if bytes.Contains(canonical, []byte(secret)) {
			t.Fatalf("source bundle disclosed %s", secret)
		}
	}
	second, repeatedDigest, err := BuildSource(root)
	if err != nil || repeatedDigest != digest || !bytes.Equal(second, payload) {
		t.Fatal("identical source did not produce byte-identical gzip and digest")
	}
	destination := filepath.Join(t.TempDir(), "private marketplace ' with spaces")
	if err := ExtractSource(payload, destination, digest); err != nil {
		t.Fatal(err)
	}
	if after := sourceCoverage(t, destination); !reflect.DeepEqual(after, coverage) {
		t.Fatalf("source delivery changed actual signature coverage: before=%+v after=%+v", coverage, after)
	}
	after := sourceSnapshot(t, destination)
	for _, member := range []string{marketplace.ManifestPath, "plugins/signed/SKILL.md", "plugins/signed/scripts/run.sh", "plugins/signed/.hidden-note", "plugins/unapproved/SKILL.md"} {
		if after[member] != before[member] {
			t.Fatalf("source bytes or mode changed for %s", member)
		}
	}
	if len(after) != 5 {
		t.Fatalf("distribution contains unexpected files: %v", after)
	}
	if !reflect.DeepEqual(before, sourceSnapshot(t, root)) {
		t.Fatal("building or extracting modified the original source")
	}
}

func TestSourceBundleRootPluginUsesExactCanonicalExclusions(t *testing.T) {
	root := t.TempDir()
	sourceFile(t, root, marketplace.ManifestPath, `{"name":"root-market","plugins":[{"name":"root-plugin","source":".","version":"1.0.0"}]}`, 0o644)
	sourceFile(t, root, "README.md", "Root source explicitly publishes this file.\n", 0o644)
	sourceFile(t, root, "scripts/run.sh", "#!/bin/sh\nexit 0\n", 0o755)
	for _, filename := range []string{".git/config", ".in_use/session", "node_modules/runtime/index.js", marketplace.SignatureFileName, archive.AttestationFileName} {
		sourceFile(t, root, filename, "EXCLUDED-ROOT-METADATA", 0o644)
	}
	before := sourceCoverage(t, root)
	payload, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(gunzipSource(t, payload), []byte("EXCLUDED-ROOT-METADATA")) {
		t.Fatal("root plugin carried Git, client data or its own signatures")
	}
	destination := filepath.Join(t.TempDir(), "root-marketplace")
	if err := ExtractSource(payload, destination, digest); err != nil {
		t.Fatal(err)
	}
	after := sourceCoverage(t, destination)
	if !reflect.DeepEqual(before.Signed, after.Signed) || len(after.Partial) != 0 {
		t.Fatalf("root plugin digest changed or omitted dependencies were claimed present: %+v", after)
	}
	if body, err := os.ReadFile(filepath.Join(destination, "README.md")); err != nil || !strings.Contains(string(body), "explicitly publishes") {
		t.Fatal("root source silently excluded signed root content")
	}
}

func TestSourceBundleRefusesUnsafeLocalLayouts(t *testing.T) {
	for _, source := range []string{"", "../outside", "/absolute", "./plugins/../signed", "plugins//signed", "plugins\\signed", "C:/outside", "plugins/name..old", "./.git", "./node_modules/plugin", "./.claude-plugin", "plugins/cafe\u0301"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			body, _ := json.Marshal(map[string]any{"name": "market", "plugins": []map[string]any{{"name": "plugin", "source": source}}})
			sourceFile(t, root, marketplace.ManifestPath, string(body), 0o644)
			if payload, _, err := BuildSource(root); err == nil || payload != nil {
				t.Fatalf("unsafe local source %q was packaged", source)
			}
		})
	}
	for _, sources := range [][2]string{{".", "./plugins/inner"}, {"./plugins/one", "plugins/one"}, {"plugins/one", "plugins/one/inner"}, {"plugins/ONE", "plugins/one"}} {
		t.Run(strings.Join(sources[:], "-"), func(t *testing.T) {
			root := t.TempDir()
			body, _ := json.Marshal(map[string]any{"name": "market", "plugins": []map[string]any{{"name": "one", "source": sources[0]}, {"name": "two", "source": sources[1]}}})
			sourceFile(t, root, marketplace.ManifestPath, string(body), 0o644)
			if _, _, err := BuildSource(root); err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("overlap did not produce an actionable refusal: %v", err)
			}
		})
	}
}

func TestSourceBundleRefusesLinksAndUnsupportedContent(t *testing.T) {
	for _, scenario := range []string{"plugin symlink", "source symlink", "manifest symlink", "manifest hardlink", "hardlink", "nested git", "empty source", "unknown source", "duplicate name"} {
		t.Run(scenario, func(t *testing.T) {
			root := sourceFixture(t)
			switch scenario {
			case "plugin symlink", "hardlink":
				original := filepath.Join(root, "company-private.txt")
				link := filepath.Join(root, "plugins", "signed", "outside")
				operation := os.Symlink
				if scenario == "hardlink" {
					operation = os.Link
				}
				if err := operation(original, link); err != nil {
					t.Skip(err)
				}
			case "source symlink":
				if err := os.Symlink(filepath.Join(root, "plugins", "signed"), filepath.Join(root, "linked")); err != nil {
					t.Skip(err)
				}
				sourceFile(t, root, marketplace.ManifestPath, `{"name":"market","plugins":[{"name":"plugin","source":"./linked"}]}`, 0o644)
			case "manifest symlink", "manifest hardlink":
				original := filepath.Join(root, marketplace.ManifestPath)
				moved := filepath.Join(root, "manifest-copy.json")
				if err := os.Rename(original, moved); err != nil {
					t.Fatal(err)
				}
				operation := os.Symlink
				if scenario == "manifest hardlink" {
					operation = os.Link
				}
				if err := operation(moved, original); err != nil {
					t.Skip(err)
				}
			case "nested git":
				sourceFile(t, root, "plugins/signed/vendor/.git/config", "PRIVATE-GIT-DATA", 0o600)
			case "empty source":
				if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
					t.Fatal(err)
				}
				sourceFile(t, root, marketplace.ManifestPath, `{"name":"market","plugins":[{"name":"plugin","source":"./empty"}]}`, 0o644)
			case "unknown source":
				sourceFile(t, root, marketplace.ManifestPath, `{"name":"market","plugins":[{"name":"plugin","source":42}]}`, 0o644)
			case "duplicate name":
				sourceFile(t, root, marketplace.ManifestPath, `{"name":"market","plugins":[{"name":"plugin","source":"./one"},{"name":"PLUGIN","source":{"source":"github","repo":"a/b"}}]}`, 0o644)
			}
			if payload, _, err := BuildSource(root); err == nil || payload != nil {
				t.Fatalf("%s was silently packaged or omitted", scenario)
			}
		})
	}
}

func TestSourceBundleRefusesUntrackedPluginContentInsteadOfChangingSignedIdentity(t *testing.T) {
	root := t.TempDir()
	sourceFile(t, root, marketplace.ManifestPath, `{"name":"market","plugins":[{"name":"plugin","source":"./plugin","version":"1"}]}`, 0o644)
	sourceFile(t, root, "plugin/SKILL.md", "published content", 0o644)
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "."}} {
		if output, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git fixture failed: %v: %s", err, output)
		}
	}
	sourceFile(t, root, "plugin/local-scratch.txt", "UNTRACKED-PRIVATE-CONTENT", 0o600)
	if payload, _, err := BuildSource(root); err == nil || payload != nil || !strings.Contains(err.Error(), "clean published snapshot") {
		t.Fatalf("untracked plugin content was distributed under a different digest: %v", err)
	}
}

func maliciousSourceTar(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestExtractSourceRefusesCorruptionTraversalLinksAndCollisions(t *testing.T) {
	root := sourceFixture(t)
	valid, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), valid...)
	corrupt[len(corrupt)-1] ^= 1
	tests := map[string]struct {
		payload []byte
		digest  string
	}{
		"bad gzip":       {[]byte("not gzip"), digest},
		"checksum":       {corrupt, digest},
		"truncated":      {valid[:len(valid)-4], digest},
		"trailing bytes": {append(append([]byte(nil), valid...), 0), digest},
		"second stream":  {append(append([]byte(nil), valid...), valid...), digest},
		"wrong digest":   {valid, "sha256:" + strings.Repeat("0", 64)},
		"bare digest":    {valid, strings.TrimPrefix(digest, "sha256:")},
		"wire limit":     {make([]byte, MaxSourceBytes+1), digest},
	}
	for label, headers := range map[string][]tar.Header{
		"traversal":      {{Name: "../escaped", Typeflag: tar.TypeReg, Mode: 0o644}},
		"absolute":       {{Name: "/escaped", Typeflag: tar.TypeReg, Mode: 0o644}},
		"symlink":        {{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../outside"}},
		"hardlink":       {{Name: "escape", Typeflag: tar.TypeLink, Linkname: "../outside"}},
		"duplicate":      {{Name: "same", Typeflag: tar.TypeReg}, {Name: "same", Typeflag: tar.TypeReg}},
		"case collision": {{Name: "Same", Typeflag: tar.TypeReg}, {Name: "same", Typeflag: tar.TypeReg}},
		"NFC collision":  {{Name: "caf\u00e9", Typeflag: tar.TypeReg}, {Name: "cafe\u0301", Typeflag: tar.TypeReg}},
	} {
		body := maliciousSourceTar(t, headers...)
		tests[label] = struct {
			payload []byte
			digest  string
		}{gzipSource(t, body), archive.DigestOf(body)}
	}
	for label, fixture := range tests {
		t.Run(label, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "new-source")
			if err := ExtractSource(fixture.payload, destination, fixture.digest); err == nil {
				t.Fatal("hostile source was accepted")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("refused extraction left files or escaped its destination: %v %v", entries, err)
			}
		})
	}
}

func TestExtractSourceRefusesUnrelatedFilesEvenWithTheirCorrectDigest(t *testing.T) {
	root := sourceFixture(t)
	// This is a valid canonical tar, but it includes repository files that source
	// delivery is not authorized to distribute. The outer digest is insufficient.
	built, err := archive.BuildExcluding(root, marketplace.PluginLimits(), ".git")
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "out")
	if err := ExtractSource(gzipSource(t, built.Payload), destination, built.Digest); err == nil || !strings.Contains(err.Error(), "outside its local plugin distribution") {
		t.Fatalf("unrelated source content was accepted: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("refused unrelated files reached the destination")
	}
}

func TestSourceBundleEnforcesExpandedFileAndAggregateLimits(t *testing.T) {
	root := sourceFixture(t)
	payload, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"expansion", "file size", "file count", "total size"} {
		t.Run(scenario, func(t *testing.T) {
			limits := marketplace.PluginLimits()
			switch scenario {
			case "expansion":
				limits.MaxArchiveBytes = int64(len(gunzipSource(t, payload))) - 1
			case "file size":
				limits.MaxFileBytes = 10
			case "file count":
				limits.MaxFiles = 2
			case "total size":
				limits.MaxTotalBytes = 10
			}
			destination := filepath.Join(t.TempDir(), "out")
			if err := extractSource(payload, destination, digest, limits); err == nil {
				t.Fatalf("expanded archive bypassed %s limit", scenario)
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("oversized archive changed destination")
			}
		})
	}
	limits := marketplace.PluginLimits()
	limits.MaxFiles = 4 // Each plugin fits, their manifest plus combined files do not.
	if _, err := sourceArchive(root, limits); err == nil || !strings.Contains(err.Error(), "combined marketplace") {
		t.Fatalf("separate plugins bypassed the combined source bound: %v", err)
	}
	large := make([]byte, MaxSourceBytes+1024)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	sourceFile(t, root, "plugins/signed/incompressible.bin", string(large), 0o644)
	if payload, _, err := BuildSource(root); err == nil || payload != nil || !strings.Contains(err.Error(), "compressed limit") {
		t.Fatalf("oversized compressed source was returned: %v", err)
	}
}

func TestExtractSourcePreservesExistingDestinationAndSymlinkTarget(t *testing.T) {
	payload, digest, err := BuildSource(sourceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"file", "empty directory", "nonempty directory", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			owned := filepath.Join(parent, "owned")
			destination := filepath.Join(parent, "destination")
			sourceFile(t, parent, "owned/preserve.txt", "KEEP-EXISTING-WORK", 0o644)
			switch scenario {
			case "file":
				sourceFile(t, parent, "destination", "KEEP-DESTINATION", 0o644)
			case "nonempty directory":
				sourceFile(t, parent, "destination/work.txt", "KEEP-DESTINATION", 0o644)
			case "empty directory":
				if err := os.Mkdir(destination, 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(owned, destination); err != nil {
					t.Skip(err)
				}
			}
			if err := ExtractSource(payload, destination, digest); err == nil {
				t.Fatal("existing destination was replaced")
			}
			body, err := os.ReadFile(filepath.Join(owned, "preserve.txt"))
			if err != nil || string(body) != "KEEP-EXISTING-WORK" {
				t.Fatal("symlink target or existing data was changed")
			}
			if scenario == "empty directory" {
				entries, err := os.ReadDir(destination)
				if err != nil || len(entries) != 0 {
					t.Fatal("existing empty directory was changed")
				}
			} else if scenario != "symlink" {
				filename := destination
				if scenario == "nonempty directory" {
					filename = filepath.Join(destination, "work.txt")
				}
				body, err := os.ReadFile(filename)
				if err != nil || string(body) != "KEEP-DESTINATION" {
					t.Fatal("existing destination work was changed")
				}
			}
		})
	}
}

func TestSourceBundlePreservesExecutableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve the Unix executable bit")
	}
	root := sourceFixture(t)
	payload, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "out")
	if err := ExtractSource(payload, destination, digest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, "plugins/signed/scripts/run.sh"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatal("executable plugin file lost its mode")
	}
}
