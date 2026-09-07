package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPolicyPreviewPreservesExistingMDMAndShowsOnlyChanges(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "export.json")
	proposal := filepath.Join(directory, "proposal.json")
	raw := []byte(`{
  "futurePolicy": {"counter": 9007199254740993, "enabled": [false, null]},
  "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "org-hook"}]}]},
  "statusLine": {"type": "command", "command": "org-status"},
  "allowManagedHooksOnly": true,
  "enabledPlugins": {"other@company": true, "disabled@company": false},
  "extraKnownMarketplaces": {
    "company": {"source": {"source": "github", "repo": "company/tools"}},
    "acme": {"source": {"repo": "acme/plugins", "source": "github"}, "autoUpdate": false}
  },
  "strictKnownMarketplaces": [
    {"source": "github", "repo": "company/tools"},
    {"source": "github", "repo": "acme/plugins"}
  ],
  "strictPluginOnlyCustomization": {"skills": false, "future": {"mode": "keep"}}
}
`)
	if err := os.WriteFile(source, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	text, code := captureStdout(t, func() int {
		return runPolicy([]string{"--from", source, "--diff", "--out", proposal,
			"--marketplace", "acme", "--repo", "acme/plugins"})
	})
	if code != exitClean {
		t.Fatalf("preview exit = %d; output: %s", code, text)
	}
	assertPolicyFileUnchanged(t, source, raw)
	before := readPolicyTestObject(t, source)
	after := readPolicyTestObject(t, proposal)
	for _, key := range []string{"futurePolicy", "hooks", "statusLine", "strictKnownMarketplaces", "extraKnownMarketplaces"} {
		assertPolicyValueEqual(t, key, after[key], before[key])
	}
	plugins := decodePolicyTestObject(t, after["enabledPlugins"])
	for key, value := range map[string]string{"other@company": "true", "disabled@company": "false", "skilltrust@acme": "true"} {
		assertPolicyValueEqual(t, key, plugins[key], []byte(value))
	}
	customization := decodePolicyTestObject(t, after["strictPluginOnlyCustomization"])
	assertPolicyValueEqual(t, "future customization", customization["future"], []byte(`{"mode":"keep"}`))
	for _, key := range []string{"skills", "agents", "hooks", "mcp"} {
		assertPolicyValueEqual(t, key, customization[key], []byte("true"))
	}
	for _, key := range []string{"allowManagedHooksOnly", "disableSideloadFlags", "disableCommandPluginSources"} {
		assertPolicyValueEqual(t, key, after[key], []byte("true"))
	}
	for _, want := range []string{"/enabledPlugins/skilltrust@acme", "/strictPluginOnlyCustomization/skills", "- false", "+ true", "owner of your existing MDM"} {
		if !strings.Contains(text, want) {
			t.Errorf("preview missing %q: %s", want, text)
		}
	}
	for _, unrelated := range []string{"org-hook", "org-status", "9007199254740993"} {
		if strings.Contains(text, unrelated) {
			t.Errorf("diff exposed unchanged setting %q: %s", unrelated, text)
		}
	}
	// Permission bits are not reliable on Windows (the same reason
	// TestOwnerOnlyWritesTightenPermissions skips there); the file still has to exist.
	info, err := os.Stat(proposal)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("proposal may contain private settings and must be owner-only: %v, %v", info, err)
	}
	text, code = captureStdout(t, func() int {
		return runPolicy([]string{"--from", proposal, "--diff", "--marketplace", "acme", "--repo", "acme/plugins"})
	})
	if code != exitClean || !strings.Contains(text, "No policy changes needed.") || strings.Contains(text, "@@") {
		t.Fatalf("repeating a proposal should have no diff: exit=%d, %s", code, text)
	}
}

func TestPolicyPreviewAddsMarketplaceWithoutReplacingOthers(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "export.json")
	proposal := filepath.Join(directory, "proposal.json")
	raw := []byte(`{"extraKnownMarketplaces":{"company":{"source":{"source":"github","repo":"company/tools"}}}}`)
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, code := captureStdout(t, func() int {
		return runPolicy([]string{"--from", source, "--out", proposal, "--marketplace", "acme", "--repo", "acme/plugins"})
	})
	if code != exitClean {
		t.Fatalf("preview exit = %d", code)
	}
	after := readPolicyTestObject(t, proposal)
	marketplaces := decodePolicyTestObject(t, after["extraKnownMarketplaces"])
	if len(marketplaces) != 2 {
		t.Fatalf("marketplaces = %s", after["extraKnownMarketplaces"])
	}
	assertPolicyValueEqual(t, "new marketplace", marketplaces["acme"], []byte(`{"source":{"repo":"acme/plugins","source":"github"}}`))
	if _, restricted := after["strictKnownMarketplaces"]; restricted {
		t.Fatal("an unrestricted export must remain unrestricted without --lockdown")
	}
	assertPolicyFileUnchanged(t, source, raw)
}

func TestPolicyPreviewRefusesConflictsAndMalformedExports(t *testing.T) {
	cases := []struct {
		name, raw string
		lockdown  bool
	}{
		{"different marketplace", `{"extraKnownMarketplaces":{"acme":{"source":{"source":"github","repo":"other/plugins"}}}}`, false},
		{"qualified marketplace", `{"extraKnownMarketplaces":{"acme":{"source":{"source":"github","repo":"acme/plugins","ref":"v1"}}}}`, false},
		{"disabled plugin", `{"enabledPlugins":{"skilltrust@acme":false}}`, false},
		{"empty allowlist", `{"strictKnownMarketplaces":[]}`, false},
		{"different allowed repo", `{"strictKnownMarketplaces":[{"source":"github","repo":"other/plugins"}]}`, false},
		{"qualified allowed repo", `{"strictKnownMarketplaces":[{"source":"github","repo":"acme/plugins","ref":"v1"}]}`, false},
		{"path qualified allowed repo", `{"strictKnownMarketplaces":[{"source":"github","repo":"acme/plugins","path":"market"}]}`, false},
		{"unevaluated pattern", `{"strictKnownMarketplaces":[{"source":"hostPattern","hostPattern":".*"}]}`, false},
		{"lockdown would remove other repo", `{"strictKnownMarketplaces":[{"source":"github","repo":"acme/plugins"},{"source":"github","repo":"company/tools"}]}`, true},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"unfinished JSON", `{"enabledPlugins":`, false},
		{"trailing JSON", `{} {}`, false},
		{"duplicate root key", `{"enabledPlugins":{},"enabledPlugins":{"skilltrust@acme":false}}`, false},
		{"duplicate plugin", `{"enabledPlugins":{"skilltrust@acme":false,"skilltrust@acme":true}}`, false},
		{"malformed marketplace map", `{"extraKnownMarketplaces":null}`, false},
		{"malformed plugin map", `{"enabledPlugins":[]}`, false},
		{"malformed plugin flag", `{"enabledPlugins":{"skilltrust@acme":"true"}}`, false},
		{"malformed boolean", `{"allowManagedHooksOnly":null}`, false},
		{"malformed customization", `{"strictPluginOnlyCustomization":false}`, false},
		{"malformed allowlist", `{"strictKnownMarketplaces":null}`, false},
		{"malformed allowlist entry", `{"strictKnownMarketplaces":[{"source":"github","repo":"acme/plugins"},null]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "export.json")
			proposal := filepath.Join(directory, "proposal.json")
			if err := os.WriteFile(source, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--from", source, "--diff", "--out", proposal, "--marketplace", "acme", "--repo", "acme/plugins"}
			if tc.lockdown {
				args = append(args, "--lockdown")
			}
			text, code := captureStdout(t, func() int { return runPolicy(args) })
			if code != exitUsage || text != "" {
				t.Fatalf("invalid proposal should fail before output: exit=%d, %s", code, text)
			}
			if _, err := os.Lstat(proposal); !os.IsNotExist(err) {
				t.Fatalf("invalid proposal created output: %v", err)
			}
			assertPolicyFileUnchanged(t, source, []byte(tc.raw))
		})
	}
}

func TestPolicyPreviewNeverClobbersAnExistingOutput(t *testing.T) {
	for _, kind := range []string{"source", "symlink", "hardlink", "existing output", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "export.json")
			output := filepath.Join(directory, "proposal.json")
			raw := []byte(`{"companySetting":"keep exactly"}`)
			if err := os.WriteFile(source, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "source":
				output = source
			case "symlink":
				if err := os.Symlink(source, output); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(source, output); err != nil {
					t.Fatal(err)
				}
			case "existing output":
				if err := os.WriteFile(output, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			case "dangling symlink":
				if err := os.Symlink(filepath.Join(directory, "missing.json"), output); err != nil {
					t.Fatal(err)
				}
			}
			_, code := captureStdout(t, func() int {
				return runPolicy([]string{"--from", source, "--diff", "--out", output, "--marketplace", "acme", "--repo", "acme/plugins"})
			})
			if code != exitUsage {
				t.Fatalf("existing output must be refused: exit=%d", code)
			}
			assertPolicyFileUnchanged(t, source, raw)
			if kind == "dangling symlink" {
				if _, err := os.Lstat(filepath.Join(directory, "missing.json")); !os.IsNotExist(err) {
					t.Fatalf("followed dangling symlink: %v", err)
				}
			} else {
				assertPolicyFileUnchanged(t, output, raw)
			}
		})
	}
}

func TestPolicyPreviewLockdownIsExplicitAndIdempotent(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "export.json")
	proposal := filepath.Join(directory, "proposal.json")
	if err := os.WriteFile(source, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, code := captureStdout(t, func() int {
		return runPolicy([]string{"--from", source, "--out", proposal, "--lockdown", "--marketplace", "acme", "--repo", "acme/plugins"})
	})
	if code != exitClean {
		t.Fatalf("preview exit = %d", code)
	}
	after := readPolicyTestObject(t, proposal)
	assertPolicyValueEqual(t, "explicit allowlist", after["strictKnownMarketplaces"], []byte(`[{"repo":"acme/plugins","source":"github"}]`))
	text, code := captureStdout(t, func() int {
		return runPolicy([]string{"--from", proposal, "--diff", "--lockdown", "--marketplace", "acme", "--repo", "acme/plugins"})
	})
	if code != exitClean || !strings.Contains(text, "No policy changes needed.") {
		t.Fatalf("repeated lockdown preview: exit=%d, %s", code, text)
	}
	assertPolicyFileUnchanged(t, source, []byte("{}"))
}

func TestPolicyDiffRequiresAnExport(t *testing.T) {
	if code := runPolicy([]string{"--diff", "--marketplace", "acme", "--repo", "acme/plugins"}); code != exitUsage {
		t.Fatalf("diff without an export must fail: exit=%d", code)
	}
}

func TestPolicyPreviewRefusesSystemManagedDirectoryAndItsAliases(t *testing.T) {
	// Model the protected directory under TempDir: even a broken guard or a mutation must
	// never attempt to create a real machine policy while running this test.
	directory := t.TempDir()
	managed := filepath.Join(directory, "managed")
	child := filepath.Join(managed, "managed-settings.d")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "export-link")
	if err := os.Symlink(managed, alias); err != nil {
		t.Fatal(err)
	}
	parents := []string{managed, child, alias}
	caseAlias := filepath.Join(directory, "MANAGED")
	if _, err := os.Stat(caseAlias); err == nil {
		parents = append(parents, caseAlias)
	}
	for _, parent := range parents {
		output := filepath.Join(parent, "proposal.json")
		err := writePolicyProposal(output, []byte("{}"), managed)
		if err == nil || !strings.Contains(err.Error(), "system managed-settings directory") {
			t.Fatalf("must refuse a system policy output %q: %v", output, err)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("wrote inside managed directory %q: %v", output, err)
		}
	}
	// Sharing a path prefix does not make a sibling directory a managed directory.
	sibling := filepath.Join(directory, "managed-export")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(sibling, "proposal.json")
	if err := writePolicyProposal(output, []byte("{}"), managed); err != nil {
		t.Fatalf("ordinary proposal directory was refused: %v", err)
	}
}

func TestPolicyPreviewMissingExportDoesNotCreateOutput(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "proposal.json")
	_, code := captureStdout(t, func() int {
		return runPolicy([]string{"--from", filepath.Join(directory, "missing.json"), "--out", output,
			"--marketplace", "acme", "--repo", "acme/plugins"})
	})
	if code != exitUsage {
		t.Fatalf("missing export must fail: exit=%d", code)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("missing export created proposal: %v", err)
	}
}

func readPolicyTestObject(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return decodePolicyTestObject(t, raw)
}

func decodePolicyTestObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func assertPolicyFileUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s was changed: read error=%v", path, err)
	}
}

func assertPolicyValueEqual(t *testing.T, name string, got, want []byte) {
	t.Helper()
	// UseNumber keeps the exact integer identity while comparing object order independently.
	decode := func(raw []byte) any {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	left, err := json.Marshal(decode(got))
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(decode(want))
	if err != nil || !bytes.Equal(left, right) {
		t.Fatalf("%s: got %s, want %s", name, got, want)
	}
}
