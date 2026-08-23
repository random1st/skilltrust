package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Every key here was read from the Claude Code settings reference, and a typo in one is the
// worst failure this file can have: an unknown key is ignored, so the policy silently does
// less than it claims while the organisation believes the fleet is locked down. This test
// exists to make inventing a key a test failure rather than a discovery.
func TestThePolicyUsesOnlyKeysClaudeCodeDefines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if code := runPolicy([]string{
		"--marketplace", "acme", "--repo", "acme/plugins", "--lockdown", "--out", path,
	}); code != exitClean {
		t.Fatalf("exit = %d", code)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("the policy must be valid JSON or Claude Code drops it whole: %v", err)
	}

	want := []string{
		"allowManagedHooksOnly",
		"disableCommandPluginSources",
		"disableSideloadFlags",
		"enabledPlugins",
		"extraKnownMarketplaces",
		"strictKnownMarketplaces",
		"strictPluginOnlyCustomization",
	}
	var got []string
	for key := range settings {
		got = append(got, key)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for index, key := range want {
		if got[index] != key {
			t.Fatalf("keys = %v, want %v", got, want)
		}
	}
}

// Forcing the plugin on is the whole point: a check a developer can switch off is a
// suggestion. The value is scoped plugin@marketplace, which is how Claude Code names one.
func TestThePolicyForcesTheCheckOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if code := runPolicy([]string{
		"--marketplace", "acme", "--repo", "acme/plugins", "--out", path,
	}); code != exitClean {
		t.Fatalf("exit = %d", code)
	}
	raw, _ := os.ReadFile(path)
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
		Strict         []any           `json:"strictKnownMarketplaces"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	if !settings.EnabledPlugins["skilltrust@acme"] {
		t.Fatalf("enabledPlugins = %v; the check must be forced on", settings.EnabledPlugins)
	}
	// Without --lockdown other marketplaces stay addable, because forbidding Anthropic's
	// official one is a decision an organisation makes deliberately, not a default.
	if settings.Strict != nil {
		t.Fatal("the marketplace allowlist must be opt-in")
	}
}

// Both arguments are required rather than guessed: a policy naming the wrong marketplace
// would force on a plugin that does not exist and lock the fleet to a repository nobody owns.
func TestThePolicyRefusesToGuess(t *testing.T) {
	if code := runPolicy([]string{"--marketplace", "acme"}); code != exitUsage {
		t.Fatalf("exit = %d; a policy must not be invented from half an answer", code)
	}
}
