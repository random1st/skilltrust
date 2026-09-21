package marketplace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, repository, path, body string) {
	t.Helper()
	target := filepath.Join(repository, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A Codex repository names its signable units in a different place and a different shape,
// and everything downstream has to stop being able to tell.
func TestACodexPluginIsReadAsAMarketplaceOfItsSkills(t *testing.T) {
	repository := t.TempDir()
	writeManifest(t, repository, CodexManifestPath, `{
	  "name": "s5d", "version": "0.22.3", "description": "decisions",
	  "skills": ["./skills/s5d", "./skills/unit-tests"]
	}`)

	manifest, err := Load(repository)
	if err != nil {
		t.Fatalf("a Codex repository could not be read: %v", err)
	}
	if manifest.Name != "s5d" {
		t.Fatalf("marketplace name is %q, want the plugin's", manifest.Name)
	}
	if len(manifest.Plugins) != 2 {
		t.Fatalf("read %d entries, want one per skill", len(manifest.Plugins))
	}

	// The entry has to be usable by the same code that reads a Claude entry: a local path
	// and a version, or nothing downstream can digest or address it.
	first := manifest.Plugins[0]
	if first.Name != "s5d" {
		t.Fatalf("entry name is %q, want the skill's directory", first.Name)
	}
	if first.Version != "0.22.3" {
		t.Fatalf("entry version is %q; Codex versions the plugin, so that is the only one there is", first.Version)
	}
	path, local := first.LocalPath(repository)
	if !local || path != filepath.Join(repository, "skills", "s5d") {
		t.Fatalf("LocalPath = %q (local=%v), want the skill directory", path, local)
	}
	if first.SourceKind() != "local" {
		t.Fatalf("source kind is %q, want local", first.SourceKind())
	}
}

// A repository with both manifests is a Claude marketplace that also ships a Codex one.
// Reading the narrower first would sign part of what it publishes and call it the whole.
func TestTheClaudeMarketplaceWinsWhenARepositoryHasBoth(t *testing.T) {
	repository := t.TempDir()
	writeManifest(t, repository, ManifestPath,
		`{"name":"everything","plugins":[{"name":"one","source":"./plugins/one"}]}`)
	writeManifest(t, repository, CodexManifestPath,
		`{"name":"part","version":"1.0.0","skills":["./skills/a"]}`)

	manifest, err := Load(repository)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "everything" {
		t.Fatalf("read %q, want the marketplace rather than the Codex plugin", manifest.Name)
	}
}

// Refusals, because each of these would otherwise produce a catalog that looks complete.
func TestACodexManifestIsRefusedRatherThanPartlyRead(t *testing.T) {
	for _, one := range []struct {
		name, body, wants string
	}{
		{name: "a path climbing out", wants: "inside the repository",
			body: `{"name":"p","version":"1","skills":["../elsewhere"]}`},
		{name: "two skills with one name", wants: "two skills named",
			body: `{"name":"p","version":"1","skills":["./a/shared","./b/shared"]}`},
		{name: "no skills at all", wants: "lists no skills",
			body: `{"name":"p","version":"1","skills":[]}`},
		{name: "no name", wants: "declares no name",
			body: `{"version":"1","skills":["./skills/a"]}`},
		{name: "not json", wants: "not a readable Codex plugin", body: `{`},
	} {
		t.Run(one.name, func(t *testing.T) {
			repository := t.TempDir()
			writeManifest(t, repository, CodexManifestPath, one.body)
			_, err := Load(repository)
			if err == nil {
				t.Fatal("accepted a manifest it should have refused")
			}
			if !strings.Contains(err.Error(), one.wants) {
				t.Fatalf("refusal does not say why: %v", err)
			}
		})
	}
}

// Neither shape present must name the file almost every repository means to have.
func TestARepositoryWithNoCatalogNamesTheUsualOne(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("a repository with no catalog loaded")
	}
	if !strings.Contains(err.Error(), "claude-plugin") {
		t.Fatalf("the refusal sends somebody to the wrong file: %v", err)
	}
}

// Read against the manifest Codex actually ships rather than one I wrote to match my
// reading of it. s5d is on this machine and is the repository that prompted this.
func TestTheShapeMatchesAManifestCodexReallyShips(t *testing.T) {
	const real = "/Users/random1st/src/s5d/.codex-plugin/plugin.json"
	raw, err := os.ReadFile(real)
	if err != nil {
		t.Skipf("no Codex manifest on this machine to check against: %v", err)
	}
	var shipped codexManifest
	if err := json.Unmarshal(raw, &shipped); err != nil {
		t.Fatalf("the shipped manifest does not fit the shape this package reads: %v", err)
	}
	if shipped.Name == "" || shipped.Version == "" || len(shipped.Skills) == 0 {
		t.Fatalf("name, version or skills came back empty from a real manifest: %+v", shipped)
	}
}
