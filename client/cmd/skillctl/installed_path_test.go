package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type installedCommandPaths struct {
	MCP   string
	Hook  string
	Error string
}

// A copied test executable gives os.Executable the same versioned installation layout
// as a release. The process only resolves paths; it never calls an installed agent.
func TestInstalledCommandPathProbe(t *testing.T) {
	if os.Getenv("SKILLTRUST_TEST_PATH_PROBE") != "1" {
		return
	}
	paths := installedCommandPaths{Hook: executablePath()}
	var err error
	paths.MCP, err = findMCPBinary()
	if err != nil {
		paths.Error = err.Error()
	}
	body, err := json.Marshal(paths)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("installed-command-paths:%s\n", body)
}

func releasePathFixture(t *testing.T) (root, cliName, mcpName string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cliName, mcpName = "skillctl", "skilltrust-mcp"
	if runtime.GOOS == "windows" {
		cliName += ".exe"
		mcpName += ".exe"
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"v1", "v2", "bin"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if dir != "bin" {
			if err := os.WriteFile(filepath.Join(root, dir, cliName), binary, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, dir, mcpName), []byte(dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root, cliName, mcpName
}

func probeInstalledPaths(t *testing.T, root, cliName string) installedCommandPaths {
	t.Helper()
	cmd := exec.Command(filepath.Join(root, "v1", cliName), "-test.run=^TestInstalledCommandPathProbe$")
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin"), "SKILLTRUST_TEST_PATH_PROBE=1")
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installed path probe: %v\n%s", err, body)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if raw, found := strings.CutPrefix(line, "installed-command-paths:"); found {
			var paths installedCommandPaths
			if err := json.Unmarshal([]byte(raw), &paths); err != nil {
				t.Fatal(err)
			}
			return paths
		}
	}
	t.Fatalf("path probe returned no result: %s", body)
	return installedCommandPaths{}
}

func TestInstalledCommandsSurviveReleaseUpgrade(t *testing.T) {
	root, cliName, mcpName := releasePathFixture(t)
	for _, name := range []string{cliName, mcpName} {
		if err := os.Symlink(filepath.Join(root, "v1", name), filepath.Join(root, "bin", name)); err != nil {
			t.Skipf("cannot create launcher symlinks here: %v", err)
		}
	}
	paths := probeInstalledPaths(t, root, cliName)
	if paths.Error != "" {
		t.Fatal(paths.Error)
	}
	for name, recorded := range map[string]string{cliName: paths.Hook, mcpName: paths.MCP} {
		launcher := filepath.Join(root, "bin", name)
		if recorded != launcher || !filepath.IsAbs(recorded) {
			t.Errorf("recorded %s as %q, want stable absolute launcher %q", name, recorded, launcher)
		}
		if err := os.Remove(launcher); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "v2", name), launcher); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "v1", name)); err != nil {
			t.Fatal(err)
		}
		installed, err := os.Stat(recorded)
		if err != nil {
			t.Errorf("recorded %s command stopped resolving after upgrade: %v", name, err)
			continue
		}
		upgraded, err := os.Stat(filepath.Join(root, "v2", name))
		if err != nil || !os.SameFile(installed, upgraded) {
			t.Errorf("recorded %s command does not resolve to the upgraded release: %v", name, err)
		}
	}
}

func TestInstalledCommandsKeepReleaseWhenPATHIsUnrelated(t *testing.T) {
	root, cliName, mcpName := releasePathFixture(t)
	// Regular files keep this refusal covered even where symlinks need privileges.
	for _, name := range []string{cliName, mcpName} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte("unrelated executable"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths := probeInstalledPaths(t, root, cliName)
	if paths.Error != "" {
		t.Fatal(paths.Error)
	}
	if paths.Hook != filepath.Join(root, "v1", cliName) || paths.MCP != filepath.Join(root, "v1", mcpName) {
		t.Fatalf("an unrelated PATH executable replaced the paired release: %+v", paths)
	}
}

func TestInstalledMCPRejectsPATHWithoutPairedBinary(t *testing.T) {
	root, cliName, mcpName := releasePathFixture(t)
	if err := os.Remove(filepath.Join(root, "v1", mcpName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", mcpName), []byte("unrelated executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths := probeInstalledPaths(t, root, cliName)
	if paths.Error == "" || paths.MCP != "" {
		t.Fatalf("setup accepted PATH without a matching paired release: %+v", paths)
	}
}

func TestInstalledHookPreservesUnrelatedNativeIntegration(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "settings.json")
	other := claudeHooks("/another-install/skillctl")
	if _, err := applyClaudeHooks(settings, other); err != nil {
		t.Fatal(err)
	}
	ours := claudeHooks("/stable-launcher/skillctl")
	if added, err := applyClaudeHooks(settings, ours); err != nil || len(added) != 1 {
		t.Fatalf("adding our hook: %v, %v", added, err)
	}
	if added, err := applyClaudeHooks(settings, ours); err != nil || len(added) != 0 {
		t.Fatalf("repeating installation duplicated the hook: %v, %v", added, err)
	}
	document, err := readSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	hooks := document["hooks"].(map[string]any)
	groups := hooks["SessionStart"].([]any)
	if len(groups) != 2 || !hookAlreadyPresent(groups, other[0].Command) || !hookAlreadyPresent(groups, ours[0].Command) {
		t.Fatalf("installing our hook changed an unrelated native integration: %v", groups)
	}
}
