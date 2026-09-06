package marketplace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PendingQuarantines counts preserved payloads without reading their contents or
// creating state. A later clean check cannot consume a person's saved edits; only
// removing or reclaiming that payload does. Sidecars left after reclaim are ignored.
// Unknown or damaged history is attention, never an empty successful inventory.
func PendingQuarantines(root string) (int, error) {
	pending, err := ListPendingQuarantines(root)
	return len(pending), err
}

// PendingQuarantine describes one unconsumed payload using its verified local
// provenance. It is local recovery metadata, not part of a signed fleet report.
type PendingQuarantine struct {
	Path      string
	Installed string
	Plugin    string
}

func ListPendingQuarantines(root string) ([]PendingQuarantine, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	entries, err := quarantineEntries(root, true)
	if err != nil {
		return nil, err
	}
	var pending []PendingQuarantine
	for _, entry := range entries {
		if entry.Name() != "by-target" || !entry.IsDir() {
			return pending, fmt.Errorf("quarantine contains history without a verified installed target")
		}
		targets, err := quarantineEntries(filepath.Join(root, entry.Name()), false)
		if err != nil {
			return pending, err
		}
		for _, target := range targets {
			if !target.IsDir() {
				return pending, fmt.Errorf("quarantine contains an unreadable target directory")
			}
			directory := filepath.Join(root, "by-target", target.Name())
			copies, err := quarantineEntries(directory, false)
			if err != nil {
				return pending, err
			}
			for _, copy := range copies {
				path := filepath.Join(directory, copy.Name())
				if !copy.IsDir() {
					// A sidecar without its payload is the normal result of reclaim.
					if copy.Type().IsRegular() && strings.HasSuffix(copy.Name(), ".json") {
						continue
					}
					return pending, fmt.Errorf("quarantine contains an unreadable saved copy")
				}
				metadata := path + ".json"
				info, err := os.Lstat(metadata)
				if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
					return pending, fmt.Errorf("quarantine contains missing or unreadable provenance")
				}
				body, err := os.ReadFile(metadata)
				if err != nil {
					return pending, err
				}
				var provenance quarantineProvenance
				if err := json.Unmarshal(body, &provenance); err != nil ||
					!filepath.IsAbs(provenance.Installed) || filepath.Clean(provenance.Installed) != provenance.Installed {
					return pending, fmt.Errorf("quarantine contains invalid provenance")
				}
				// Validate the saved identity without requiring the original client to
				// remain installed: uninstalling it must not hide the saved copy.
				if err := checkQuarantineProvenance(path, provenance.Installed, provenance.Plugin); err != nil {
					return pending, err
				}
				pending = append(pending, PendingQuarantine{Path: path, Installed: provenance.Installed, Plugin: provenance.Plugin})
			}
		}
	}
	return pending, nil
}

func quarantineEntries(path string, missingOK bool) ([]os.DirEntry, error) {
	info, err := os.Lstat(path)
	if missingOK && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("quarantine path is not a regular directory")
	}
	return os.ReadDir(path)
}
