package main

import (
	"fmt"
	"path/filepath"

	"github.com/random1st/skilltrust/internal/marketplace"
)

type savedSkillChange struct {
	Plugin      string   `json:"plugin"`
	Path        string   `json:"path"`
	NextCommand []string `json:"next_command"`
}

// The statusline points to doctor. Saved edits must still be discoverable here
// after a later check passes, using the same provenance as exact recovery.
func statusWithSavedChanges(out machineStatus) machineStatus {
	saved, err := marketplace.ListPendingQuarantines(quarantineRoot())
	if err != nil {
		out.SavedChangesError = err.Error()
	}
	for _, copy := range saved {
		result, err := savedChangeTarget(copy)
		if err != nil {
			out.SavedChangesError = err.Error()
			continue
		}
		command, _ := quarantineCommands(result, copy.Path, "", "")
		if len(command) == 0 {
			out.SavedChangesError = "a saved change has no verified recovery target"
			continue
		}
		out.SavedChanges = append(out.SavedChanges, savedSkillChange{Plugin: copy.Plugin, Path: copy.Path, NextCommand: command})
	}
	if out.SavedChangesError == "" && len(out.SavedChanges) == 0 {
		return out
	}
	if out.Status == "connected" || out.Status == "local_checked" || out.Status == "approvals_checked" {
		out.Status, out.Title = "needs_attention", "Local changes are saved for review"
		out.NextAction = &nextAction{"review_saved_change", "user", "Your saved edits remain available. Review the exact copy before choosing whether to keep it."}
		out.NextCommand = []string{commandName(), "doctor", "--json"}
		if len(out.SavedChanges) > 0 {
			out.NextCommand = out.SavedChanges[0].NextCommand
		}
		if out.SavedChangesError != "" {
			out.Title = "Some saved changes could not be identified"
		}
	}
	return out
}

func savedChangeTarget(copy marketplace.PendingQuarantine) (marketplace.Result, error) {
	plugin := filepath.Dir(copy.Installed)
	market := filepath.Dir(plugin)
	cache := filepath.Dir(market)
	plugins := filepath.Dir(cache)
	home := filepath.Dir(plugins)
	version, name := filepath.Base(copy.Installed), filepath.Base(market)
	if filepath.Base(plugin) != copy.Plugin || filepath.Base(cache) != "cache" || filepath.Base(plugins) != "plugins" ||
		!filepath.IsAbs(home) || marketplace.InstalledPath(home, name, copy.Plugin, version) != copy.Installed {
		return marketplace.Result{}, fmt.Errorf("saved copy %q has an unsupported installed location", copy.Path)
	}
	return marketplace.Result{ClientHome: home, Marketplace: name, Plugin: copy.Plugin, Version: version}, nil
}
