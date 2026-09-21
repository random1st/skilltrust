// Package marketplace reads a Claude Code plugin marketplace and locates what it installed.
//
// This is where the tool stops inventing a distribution mechanism and signs the one that
// already exists. Claude Code gives an organisation a catalog (marketplace.json), commit
// pinning, and managed settings that decide which marketplaces a machine may use at all.
// What it does not give is a signature over that catalog, a way to withdraw a version
// already installed, or any check that the installed copy is still what was fetched — the
// plugin cache is an ordinary directory an agent can write to, and nothing looks at it again.
//
// Those three gaps are the product. Everything here exists to name the same artifacts Claude
// Code names, so an organisation signs what it already publishes rather than maintaining a
// second catalog that can drift from the real one.
package marketplace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/random1st/skilltrust/catalog"
)

// ManifestPath is where a marketplace repository keeps its catalog.
const ManifestPath = ".claude-plugin/marketplace.json"

// PluginManifestPath is where a plugin keeps its own manifest.
const PluginManifestPath = ".claude-plugin/plugin.json"

// CodexManifestPath is Codex's own manifest, and the reason this package reads two shapes.
//
// Codex has no marketplace format of its own: `codex plugin marketplace add` clones a
// repository and reads the same .claude-plugin/marketplace.json, leaving an install record
// beside it. Checked on a real machine rather than assumed — every marketplace under
// ~/.codex/.tmp/marketplaces carries a .claude-plugin directory.
//
// What it does have is a plugin manifest at the repository root listing skill directories
// instead of plugins. A repository published for Codex therefore names its signable units
// in a different place and a different shape, and nothing below this file needs to know:
// both are turned into the same Manifest.
const CodexManifestPath = ".codex-plugin/plugin.json"

// Entry is one plugin listed by a marketplace.
//
// Source is deliberately left as raw JSON. It is a string for a path inside the repository
// and an object for the several git and archive forms, and this package only needs to tell
// those two apart; decoding every variant would mean tracking a schema that belongs to
// another product and failing to load a catalog the moment it grows a form we have not seen.
type Entry struct {
	Name        string          `json:"name"`
	Source      json.RawMessage `json:"source"`
	Version     string          `json:"version,omitempty"`
	Description string          `json:"description,omitempty"`
}

// Manifest is a marketplace catalog.
type Manifest struct {
	Name    string  `json:"name"`
	Owner   any     `json:"owner,omitempty"`
	Plugins []Entry `json:"plugins"`
}

// Load reads a repository's catalog, in whichever shape it publishes one.
//
// The Claude marketplace is tried first and a Codex plugin second, in that order because a
// repository that has both is a Claude marketplace that also ships a Codex manifest — s5d
// is exactly that — and the marketplace is the broader statement: it names plugins, one of
// which the Codex manifest then details. Reading the narrower one first would sign part of
// what the repository publishes and call it the whole.
func Load(repository string) (*Manifest, error) {
	path := filepath.Join(repository, filepath.FromSlash(ManifestPath))
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		codex, codexErr := loadCodex(repository)
		if codexErr == nil {
			return codex, nil
		}
		if os.IsNotExist(codexErr) {
			// Neither shape is present. The Claude path is named because it is the one
			// almost every repository means to have, and "no .codex-plugin either" would
			// send somebody looking for the wrong file.
			return nil, err
		}
		return nil, codexErr
	}
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s is not a readable marketplace: %w", path, err)
	}
	if manifest.Name == "" {
		return nil, fmt.Errorf("%s names no marketplace", path)
	}
	return &manifest, nil
}

// LocalPath returns where a plugin's source lives inside the marketplace repository, and
// whether it lives there at all.
//
// Only a string source is local. Every object form — github, url, git-subdir, archive —
// points somewhere this repository does not control, so its bytes are not something the
// marketplace owner can sign for. Saying so is the point: an organisation signing a catalog
// that re-exports third-party plugins should see exactly which of them its signature does
// not cover, rather than have them quietly included or quietly dropped.
func (e Entry) LocalPath(repository string) (string, bool) {
	var source string
	if err := json.Unmarshal(e.Source, &source); err != nil {
		return "", false
	}
	if source == "" || strings.Contains(source, "..") {
		return "", false
	}
	return filepath.Join(repository, filepath.FromSlash(strings.TrimPrefix(source, "./"))), true
}

// SourceKind names the form of a plugin source, for reporting.
func (e Entry) SourceKind() string {
	var asString string
	if err := json.Unmarshal(e.Source, &asString); err == nil {
		return "local"
	}
	var object struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(e.Source, &object); err == nil && object.Source != "" {
		return object.Source
	}
	return "unknown"
}

// ResolveVersion returns the version a plugin will be cached under.
//
// The marketplace entry wins over the plugin's own manifest, which is the precedence Claude
// Code documents. An empty result means the version comes from a fallback this tool cannot
// reproduce, so the cache directory cannot be named and the plugin is reported as
// unverifiable rather than guessed at.
func (e Entry) ResolveVersion(repository string) string {
	if e.Version != "" {
		return e.Version
	}
	directory, local := e.LocalPath(repository)
	if !local {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(PluginManifestPath)))
	if err != nil {
		return ""
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ""
	}
	return manifest.Version
}

// CacheRoot is where Claude Code keeps installed plugins.
func CacheRoot(claudeHome string) string {
	// An empty home used to produce the relative path ./plugins/cache, so a caller that
	// forgot to default it searched the working directory, found nothing, and reported
	// every plugin as not installed — a wrong answer indistinguishable from a right one.
	// One caller had already forgotten. Defaulting here removes the trap rather than
	// asking every future call site to remember it.
	if claudeHome == "" {
		claudeHome = DefaultClaudeHome()
	}
	return filepath.Join(claudeHome, "plugins", "cache")
}

// InstalledPath is the directory a given plugin version is installed into.
func InstalledPath(claudeHome, marketplaceName, pluginName, version string) string {
	return filepath.Join(CacheRoot(claudeHome), marketplaceName, pluginName, version)
}

// PluginCache locates what a marketplace client installed: one copy per plugin, in the
// directory named by the version the catalog signs.
//
// This is the only Locator that knows about versions, because it is the only layout that has
// them. When the signed release is not there but another is, that is reported as a copy with
// no path rather than as an absence — the two are different findings and the difference is
// only visible from here.
func PluginCache(claudeHome, marketplaceName string) Locator {
	return func(managed catalog.Managed) []InstalledCopy {
		installed := InstalledPath(claudeHome, marketplaceName, managed.Name, managed.Version)
		if _, err := os.Stat(installed); os.IsNotExist(err) {
			others := InstalledVersions(claudeHome, marketplaceName, managed.Name)
			if len(others) == 0 {
				return nil
			}
			return []InstalledCopy{{OtherVersion: others[0]}}
		}
		// Any other stat failure is left to the digest, which reports it as unverifiable
		// with the reason attached rather than as a plugin nobody installed.
		return []InstalledCopy{{Path: installed}}
	}
}

// InstalledVersions lists the versions of a plugin present in the cache, so a report can say
// that the wrong one is on disk rather than only that the right one is missing.
func InstalledVersions(claudeHome, marketplaceName, pluginName string) []string {
	entries, err := os.ReadDir(filepath.Join(CacheRoot(claudeHome), marketplaceName, pluginName))
	if err != nil {
		return nil
	}
	var versions []string
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	return versions
}

// DefaultClaudeHome is where Claude Code keeps its state.
func DefaultClaudeHome() string {
	if override := os.Getenv("CLAUDE_CONFIG_DIR"); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".claude"
	}
	return filepath.Join(home, ".claude")
}

// hasDependencies reports whether a plugin tree carries installed dependency code, which the
// publisher's signature does not cover.
func hasDependencies(directory string) bool {
	info, err := os.Stat(filepath.Join(directory, "node_modules"))
	return err == nil && info.IsDir()
}
