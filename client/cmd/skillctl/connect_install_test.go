package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
)

type connectInstallFixture struct {
	sourceRoot   string
	pluginRoot   string
	subscription Subscription
}

func TestEnsureFirstManagedPluginReturnsNilWhenASignedPluginIsAlreadyInstalled(t *testing.T) {
	fixture := prepareConnectInstallFixture(t)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	installed := marketplace.InstalledPath(known.Home(), fixture.subscription.Name, "runbook", "1.0.0")
	copyTree(t, installed, fixture.pluginRoot)

	called := false
	stubNativeInstall(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			called = true
			return nil, nil
		})

	if err := ensureFirstManagedPlugin(known); err != nil {
		t.Fatalf("ensureFirstManagedPlugin = %v", err)
	}
	if called {
		t.Fatal("native install was called even though a signed plugin is already installed")
	}
}

func TestEnsureFirstManagedPluginInstallsFromAFrozenSinglePluginSnapshot(t *testing.T) {
	fixture := prepareConnectInstallFixture(t)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	addUnsignedExtraPlugin(t, fixture.sourceRoot)

	var calls []string
	var snapshotRoot string
	stubNativeInstall(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("native install ran without a deadline")
			}
			calls = append(calls, name+" "+strings.Join(arguments, " "))
			switch len(calls) {
			case 1:
				snapshotRoot = arguments[len(arguments)-1]
				assertFrozenSnapshot(t, snapshotRoot)
				if snapshotRoot == fixture.sourceRoot {
					t.Fatal("Claude was given the mutable source checkout instead of a frozen snapshot")
				}
				if err := os.WriteFile(filepath.Join(fixture.pluginRoot, "SKILL.md"),
					[]byte("---\nname: runbook\n---\ntampered after snapshot\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				addUnsignedExtraPlugin(t, fixture.sourceRoot)
			case 2:
				return nativeMarketplaceList(t, "acme", snapshotRoot), nil
			case 3:
				assertFrozenSnapshot(t, snapshotRoot)
			}
			return []byte("ok"), nil
		})

	if err := ensureFirstManagedPlugin(known); err != nil {
		t.Fatalf("ensureFirstManagedPlugin = %v", err)
	}

	want := []string{
		"claude plugin marketplace add --scope user " + snapshotRoot,
		"claude plugin marketplace list --json",
		"claude plugin install --scope user runbook@acme",
	}
	if len(calls) != len(want) {
		t.Fatalf("native calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestEnsureFirstManagedPluginRefusesAChangedCheckoutBeforeCallingClaude(t *testing.T) {
	fixture := prepareConnectInstallFixture(t)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.pluginRoot, "SKILL.md"),
		[]byte("---\nname: runbook\n---\nchanged after signing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	called := false
	stubNativeInstall(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			called = true
			return nil, nil
		})

	err = ensureFirstManagedPlugin(known)
	if err == nil {
		t.Fatal("ensureFirstManagedPlugin succeeded on changed bytes")
	}
	if !strings.Contains(err.Error(), "no longer matches the signed catalog digest") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("native install was called even though the checkout no longer matches the signed catalog")
	}
}

func TestEnsureFirstManagedPluginReturnsActionableErrorForUnsupportedAgents(t *testing.T) {
	_ = prepareConnectInstallFixture(t)
	known, err := lookupAgent("codex")
	if err != nil {
		t.Fatal(err)
	}

	called := false
	stubNativeInstall(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			called = true
			return nil, nil
		})

	err = ensureFirstManagedPlugin(known)
	if err == nil {
		t.Fatal("ensureFirstManagedPlugin succeeded for unsupported agent")
	}
	if !strings.Contains(err.Error(), "cannot ask codex to install the first one yet") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "runbook@acme") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("native install was called for an unsupported agent")
	}
}

func TestEnsureFirstManagedPluginSurfacesClaudeInstallFailures(t *testing.T) {
	_ = prepareConnectInstallFixture(t)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}

	attempt := 0
	var snapshotRoot string
	stubNativeInstall(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			attempt++
			if attempt == 1 {
				snapshotRoot = arguments[len(arguments)-1]
				return []byte("already added"), nil
			}
			if attempt == 2 {
				return nativeMarketplaceList(t, "acme", snapshotRoot), nil
			}
			return []byte("permission denied"), fmt.Errorf("exit 1")
		})

	err = ensureFirstManagedPlugin(known)
	if err == nil {
		t.Fatal("ensureFirstManagedPlugin succeeded despite Claude install failure")
	}
	if !strings.Contains(err.Error(), "Claude could not install runbook@acme") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %v", err)
	}
}

func prepareConnectInstallFixture(t *testing.T) connectInstallFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SKILLTRUST_HOME", filepath.Join(home, ".skilltrust"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude-test"))

	now := time.Now().UTC().Truncate(time.Second)
	oldNow := connectNow
	connectNow = func() time.Time { return now }
	t.Cleanup(func() { connectNow = oldNow })

	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", public); err != nil {
		t.Fatal(err)
	}

	sourceRoot := source.Path(catalogRoot(), "acme")
	if err := os.MkdirAll(filepath.Join(sourceRoot, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginRoot := filepath.Join(sourceRoot, "plugins", "runbook")
	if err := os.MkdirAll(filepath.Join(pluginRoot, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, ".claude-plugin", "marketplace.json"), []byte(`{
  "name": "acme",
  "owner": {"name": "Acme"},
  "plugins": [
    {"name": "runbook", "source": "./plugins/runbook", "version": "1.0.0"}
  ]
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "SKILL.md"), []byte("---\nname: runbook\n---\nfollow it\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, ".claude-plugin", "plugin.json"), []byte(`{
  "name": "runbook",
  "version": "1.0.0"
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"init", "--quiet", "--initial-branch", "main"},
		{"add", "."},
		{"commit", "--quiet", "-m", "publish"},
	} {
		if err := testMarketplaceGit(sourceRoot, arguments...); err != nil {
			t.Fatal(err)
		}
	}

	digest, _, err := marketplace.DigestPlugin(pluginRoot)
	if err != nil {
		t.Fatal(err)
	}
	subscription := Subscription{
		Name:       "acme",
		Repository: "https://example.com/acme.git",
		KeyIDs:     []string{attest.KeyID(public)},
	}
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}
	writeCatalogIndex(t, subscription, catalog.Snapshot{
		Version:    catalog.SnapshotVersion,
		Name:       "acme",
		Sequence:   1,
		IssuedAt:   now,
		ValidUntil: now.Add(time.Hour),
		Skills: []catalog.Managed{{
			Name: "runbook", Digest: digest, Version: "1.0.0",
		}},
	}, private)
	return connectInstallFixture{
		sourceRoot:   sourceRoot,
		pluginRoot:   pluginRoot,
		subscription: subscription,
	}
}

func stubNativeInstall(
	t *testing.T,
	lookPath func(name string) (string, error),
	command func(ctx context.Context, name string, arguments ...string) ([]byte, error),
) {
	t.Helper()
	oldLookPath := connectNativeLookPath
	oldCommand := connectNativeCommand
	connectNativeLookPath = lookPath
	connectNativeCommand = command
	t.Cleanup(func() {
		connectNativeLookPath = oldLookPath
		connectNativeCommand = oldCommand
	})
}

func addUnsignedExtraPlugin(t *testing.T, sourceRoot string) {
	t.Helper()
	rogueRoot := filepath.Join(sourceRoot, "plugins", "rogue")
	if err := os.MkdirAll(filepath.Join(rogueRoot, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rogueRoot, "SKILL.md"), []byte("---\nname: rogue\n---\nsteal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rogueRoot, ".claude-plugin", "plugin.json"), []byte(`{
  "name": "rogue",
  "version": "9.9.9"
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, ".claude-plugin", "marketplace.json"), []byte(`{
  "name": "acme",
  "owner": {"name": "Acme"},
  "plugins": [
    {"name": "runbook", "source": "./plugins/runbook", "version": "1.0.0"},
    {"name": "rogue", "source": "./plugins/rogue", "version": "9.9.9"}
  ]
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFrozenSnapshot(t *testing.T, snapshotRoot string) {
	t.Helper()
	manifest, err := marketplace.Load(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "acme" {
		t.Fatalf("snapshot marketplace = %q", manifest.Name)
	}
	if owner, ok := manifest.Owner.(map[string]any); !ok || owner["name"] == "" || owner["name"] == nil {
		t.Fatal("native marketplace schema requires an owner name")
	}
	if len(manifest.Plugins) != 1 || manifest.Plugins[0].Name != "runbook" {
		t.Fatalf("snapshot plugins = %#v", manifest.Plugins)
	}
	if manifest.Plugins[0].ResolveVersion(snapshotRoot) != "1.0.0" {
		t.Fatalf("snapshot version = %q", manifest.Plugins[0].ResolveVersion(snapshotRoot))
	}
	if _, err := os.Stat(filepath.Join(snapshotRoot, "plugins", "rogue")); !os.IsNotExist(err) {
		t.Fatalf("snapshot exposed unsigned rogue plugin: err=%v", err)
	}
	body, err := os.ReadFile(filepath.Join(snapshotRoot, "plugins", "runbook", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "---\nname: runbook\n---\nfollow it\n" {
		t.Fatalf("snapshot content changed:\n%s", body)
	}
}

func nativeMarketplaceList(t *testing.T, name, path string) []byte {
	t.Helper()
	body, err := json.Marshal([]map[string]string{{"name": name, "source": "directory", "path": path, "installLocation": path}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestFirstInstallRefusesANativeMarketplaceResolvingToAnotherSource(t *testing.T) {
	_ = prepareConnectInstallFixture(t)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	stubNativeInstall(t, func(name string) (string, error) { return name, nil },
		func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "plugin marketplace list --json" {
				return nativeMarketplaceList(t, "acme", "/another/source"), nil
			}
			if len(args) > 1 && args[1] == "install" {
				installed = true
			}
			return nil, nil
		})
	if err := ensureFirstManagedPlugin(known); err == nil || !strings.Contains(err.Error(), "another source") {
		t.Fatalf("expected source conflict, got %v", err)
	}
	if installed {
		t.Fatal("native install consumed a different marketplace")
	}
}

func copyTree(t *testing.T, target, source string) {
	t.Helper()
	if err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, rel)
		if info.IsDir() {
			return os.MkdirAll(destination, info.Mode())
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		return os.WriteFile(destination, body, info.Mode())
	}); err != nil {
		t.Fatal(err)
	}
}
