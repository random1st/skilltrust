package marketplace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// codexManifest is what Codex keeps at a repository's root.
//
// It describes one plugin and lists the skill directories inside it, where a Claude
// marketplace describes many plugins and lists where each lives. The two are read into the
// same Manifest so that signing, digesting and publishing never learn which client a
// repository was written for.
type codexManifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Skills      []string `json:"skills"`
}

// loadCodex reads a Codex plugin manifest as a marketplace of its skills.
//
// Each skill directory becomes an entry, because a skill is what somebody installs and
// therefore what a signature has to be about. The plugin's own version is carried onto
// every one of them: Codex versions the plugin rather than the skills, so that is the only
// version there is, and inventing a per-skill one would put a number in a catalog that
// matches nothing on disk.
func loadCodex(repository string) (*Manifest, error) {
	path := filepath.Join(repository, filepath.FromSlash(CodexManifestPath))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var codex codexManifest
	if err := json.Unmarshal(raw, &codex); err != nil {
		return nil, fmt.Errorf("%s is not a readable Codex plugin: %w", path, err)
	}
	if codex.Name == "" {
		return nil, fmt.Errorf("%s declares no name, so nothing it lists can be addressed", path)
	}

	manifest := &Manifest{Name: codex.Name}
	seen := map[string]struct{}{}
	for _, source := range codex.Skills {
		clean := strings.TrimPrefix(strings.TrimSpace(source), "./")
		if clean == "" || strings.Contains(clean, "..") {
			// Refused rather than skipped: a path that climbs out of the repository is not
			// a skill this publisher can vouch for, and signing the rest quietly would
			// produce a catalog that looks complete and is not.
			return nil, fmt.Errorf("%s lists %q, which is not a path inside the repository", path, source)
		}
		name := filepath.Base(clean)
		if _, repeat := seen[name]; repeat {
			// Two directories with the same basename would collapse into one entry and the
			// second would silently replace the first in the catalog.
			return nil, fmt.Errorf("%s lists two skills named %q; a catalog addresses them by name", path, name)
		}
		seen[name] = struct{}{}

		source, err := json.Marshal("./" + clean)
		if err != nil {
			return nil, err
		}
		manifest.Plugins = append(manifest.Plugins, Entry{
			Name: name, Source: source, Version: codex.Version, Description: codex.Description,
		})
	}
	if len(manifest.Plugins) == 0 {
		return nil, fmt.Errorf("%s lists no skills", path)
	}
	return manifest, nil
}
