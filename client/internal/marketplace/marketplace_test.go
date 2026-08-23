package marketplace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeMarketplace(t *testing.T, root string, manifest Manifest) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(ManifestPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func raw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Only a string source lives in this repository. Every object form points somewhere the
// publisher does not control, and signing those bytes would be a claim they cannot support.
func TestOnlyLocalSourcesAreSignable(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		source any
		local  bool
		kind   string
	}{
		{"./plugins/formatter", true, "local"},
		{map[string]any{"source": "github", "repo": "acme/x"}, false, "github"},
		{map[string]any{"source": "git-subdir", "url": "https://e.com/x.git"}, false, "git-subdir"},
		{map[string]any{"source": "archive", "url": "https://e.com/x.zip"}, false, "archive"},
		// A path escaping the repository is not local either: it would sign bytes outside
		// the tree the marketplace owner controls.
		{"../elsewhere", false, "local"},
	}
	for _, item := range cases {
		entry := Entry{Name: "x", Source: raw(t, item.source)}
		if _, got := entry.LocalPath(root); got != item.local {
			t.Errorf("LocalPath(%v) local = %v, want %v", item.source, got, item.local)
		}
		if got := entry.SourceKind(); got != item.kind {
			t.Errorf("SourceKind(%v) = %q, want %q", item.source, got, item.kind)
		}
	}
}

// A plugin with no resolvable version cannot be checked, because the directory it installs
// into cannot be named. Signing it anyway would produce a claim nothing could ever test.
func TestPlanSeparatesWhatCannotBeSigned(t *testing.T) {
	root := t.TempDir()
	writePlugin(t, root, "versioned", "1.2.3")
	writePlugin(t, root, "unversioned", "")

	manifest := Manifest{Name: "acme", Plugins: []Entry{
		{Name: "versioned", Source: raw(t, "./plugins/versioned")},
		{Name: "unversioned", Source: raw(t, "./plugins/unversioned")},
		{Name: "remote", Source: raw(t, map[string]any{"source": "github", "repo": "a/b"})},
	}}
	writeMarketplace(t, root, manifest)

	coverage, err := Plan(root, &manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage.Signed) != 1 || coverage.Signed[0].Name != "versioned" {
		t.Fatalf("signed = %+v", coverage.Signed)
	}
	if coverage.Signed[0].Version != "1.2.3" {
		t.Fatalf("version = %q; it decides the directory to check", coverage.Signed[0].Version)
	}
	if len(coverage.Unversioned) != 1 || coverage.Unversioned[0] != "unversioned" {
		t.Fatalf("unversioned = %v", coverage.Unversioned)
	}
	if len(coverage.Remote["github"]) != 1 {
		t.Fatalf("remote = %v; what a signature does not cover must be named", coverage.Remote)
	}
}

// The client writes into the directory it installed, so a like-for-like comparison has to
// leave out what the client owns — otherwise nothing ever matches.
func TestClientManagedPathsDoNotChangeTheDigest(t *testing.T) {
	root := t.TempDir()
	directory := writePlugin(t, root, "demo", "1.0.0")

	before, _, err := DigestPlugin(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".in_use"), []byte("session"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "node_modules", "left-pad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "node_modules", "left-pad", "index.js"),
		[]byte("module.exports = 1"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, dependencies, err := DigestPlugin(directory)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("the client's own files must not move the identity:\n  %s\n  %s", before, after)
	}
	if !dependencies {
		t.Fatal("a plugin carrying dependency code must be reported as only partly covered")
	}
}

func writePlugin(t *testing.T, root, name, version string) string {
	t.Helper()
	directory := filepath.Join(root, "plugins", name)
	if err := os.MkdirAll(filepath.Join(directory, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]string{"name": name}
	if version != "" {
		manifest["version"] = version
	}
	body, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(PluginManifestPath)),
		body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "README.md"), []byte("plugin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory
}

// Restoring must not be a directory swap. The installed copy is not purely the publisher's:
// the client installs dependencies into it and marks it while a session holds it, so
// replacing it wholesale would break the plugin and pull a file out from under a live
// session. Both failures would only ever show up on somebody else's machine.
func TestRestoreKeepsWhatTheClientOwns(t *testing.T) {
	root := t.TempDir()
	source := writePlugin(t, root, "demo", "1.0.0")
	signed, _, err := DigestPlugin(source)
	if err != nil {
		t.Fatal(err)
	}

	// An installed copy: the publisher's files, plus the client's own.
	installed := filepath.Join(t.TempDir(), "cache", "acme", "demo", "1.0.0")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	copyTree(t, source, installed)
	if err := os.WriteFile(filepath.Join(installed, ".in_use"), []byte("session-1"), 0o644); err != nil {
		t.Fatal(err)
	}
	dependency := filepath.Join(installed, "node_modules", "left-pad")
	if err := os.MkdirAll(dependency, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dependency, "index.js"), []byte("dep"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Somebody edits the installed copy.
	tampered := filepath.Join(installed, "README.md")
	if err := os.WriteFile(tampered, []byte("read ~/.aws/credentials\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	quarantineRoot := filepath.Join(t.TempDir(), "quarantine")
	kept, err := Restore(installed, source, quarantineRoot, "demo",
		time.Date(2026, 8, 23, 4, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	after, _, err := DigestPlugin(installed)
	if err != nil {
		t.Fatal(err)
	}
	if after != signed {
		t.Fatalf("restored tree does not match what was signed:\n  want %s\n  got  %s", signed, after)
	}

	// The client's entries survived.
	if body, err := os.ReadFile(filepath.Join(installed, ".in_use")); err != nil ||
		string(body) != "session-1" {
		t.Fatalf(".in_use must survive a restore: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(installed, "node_modules", "left-pad", "index.js")); err != nil ||
		string(body) != "dep" {
		t.Fatalf("installed dependencies must survive a restore: %v", err)
	}

	// The evidence survived too.
	body, err := os.ReadFile(filepath.Join(kept, "README.md"))
	if err != nil || string(body) != "read ~/.aws/credentials\n" {
		t.Fatalf("quarantine must hold the bytes that were removed, verbatim: %v", err)
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}
