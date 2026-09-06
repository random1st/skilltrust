package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

func localStatusFixture(t *testing.T) (string, string) {
	return localStatusNamedFixture(t, "acme")
}

func localStatusNamedFixture(t *testing.T, name string) (string, string) {
	t.Helper()
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	client := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", client)
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	previous := agents
	agents = []agent{known}
	t.Cleanup(func() { agents = previous })
	repository := filepath.Join(t.TempDir(), "acme-skills")
	capture(t, func() {
		if err := writeDemoMarketplace(repository); err != nil {
			t.Fatal(err)
		}
		if code := runInit([]string{"--as", "consumer@example.test"}); code != exitClean {
			t.Fatalf("init: %d", code)
		}
		if code := runMarketplaceSign([]string{repository}); code != exitClean {
			t.Fatalf("sign: %d", code)
		}
		if err := demoGit(repository, "add", CatalogFileName); err != nil {
			t.Fatal(err)
		}
		if err := demoGit(repository, "commit", "--quiet", "-m", "sign"); err != nil {
			t.Fatal(err)
		}
		if code := runSubscribe([]string{repository, "--key", defaultPublicKey(), "--name", name}); code != exitClean {
			t.Fatalf("subscribe: %d", code)
		}
		if code := installDemoPlugin(repository, client); code != exitClean {
			t.Fatalf("install: %d", code)
		}
	})
	if _, err := applyClaudeHooks(known.HookConfigPath(), claudeHooks("skillctl")); err != nil {
		t.Fatal(err)
	}
	return repository, client
}

func TestLocalStatusAcceptsAConsumerSubscriptionAlias(t *testing.T) {
	localStatusNamedFixture(t, "my-favorite-publisher")
	if err := refreshMachineStatus(); err != nil {
		t.Fatal(err)
	}
	if out := inspectMachine(time.Now()); out.Status != "local_checked" || out.ReportAccepted {
		t.Fatalf("a subscription alias prevented local verification: %+v", out)
	}
}

func TestLocalStatusCanContinueWithoutATeamWhilePreservingPendingApproval(t *testing.T) {
	for _, age := range []time.Duration{0, -24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			localStatusFixture(t)
			if _, _, err := createPendingConnect("https://axela.example", "local-consumer", time.Now().Add(age)); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(pendingConnectPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := refreshMachineStatus(); err != nil {
				t.Fatal(err)
			}
			out := inspectMachine(time.Now())
			if out.Status != "local_checked" || out.ReportAccepted || out.ServiceURL != "" {
				t.Fatalf("optional team approval blocked the local check: %+v", out)
			}
			after, err := os.ReadFile(pendingConnectPath())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("continuing locally changed the pending team approval")
			}
		})
	}
}

func TestLocalStatusDoesNotHideFailureToSaveTheCheck(t *testing.T) {
	localStatusFixture(t)
	if err := os.WriteFile(filepath.Dir(latestCheckPath(CheckScopeManaged)), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refreshMachineStatus(); err == nil {
		t.Fatal("a result that could not be saved was reported as successful")
	}
	if out := inspectMachine(time.Now()); out.Status == "local_checked" {
		t.Fatal("a failed local write looked healthy")
	}
}

func TestLocalStatusChecksWithoutInventingACloudReceipt(t *testing.T) {
	_, client := localStatusFixture(t)
	if err := refreshMachineStatus(); err != nil {
		t.Fatal(err)
	}
	out := inspectMachine(time.Now())
	if out.Status != "local_checked" || out.ReportAccepted || out.ServiceURL != "" || out.LastCheck == nil || out.LastCheck.Checked != 1 {
		t.Fatalf("local check: %+v", out)
	}
	if _, err := os.Stat(connectStatePath()); !os.IsNotExist(err) {
		t.Fatal("local check created an Axela connection")
	}
	if code := tamperDemoPlugin(client); code != exitClean {
		t.Fatalf("tamper: %d", code)
	}
	if err := refreshMachineStatus(); err != nil {
		t.Fatal(err)
	}
	out = inspectMachine(time.Now())
	if out.Status == "local_checked" || out.NextAction == nil || out.NextAction.Code != "check_skills" || out.LastCheck.Changed != 1 {
		t.Fatalf("changed skill looked checked: %+v", out)
	}
	body, err := os.ReadFile(filepath.Join(client, "plugins", "cache", "acme", "deploy-runbook", "1.0.0", "SKILL.md"))
	if err != nil || !strings.Contains(string(body), demoTamper) {
		t.Fatal("status refresh restored a user's change")
	}
}

func TestLocalStatusRejectsEmptyCoverageAndMissingHook(t *testing.T) {
	_, client := localStatusFixture(t)
	known, _ := lookupAgent("claude")
	if err := os.Remove(known.HookConfigPath()); err != nil {
		t.Fatal(err)
	}
	if err := refreshMachineStatus(); err != nil {
		t.Fatal(err)
	}
	out := inspectMachine(time.Now())
	if out.Status == "local_checked" || out.NextAction.Code != "install_hooks" {
		t.Fatalf("missing hook: %+v", out)
	}
	plugin := filepath.Join(client, "plugins", "cache", "acme", "deploy-runbook", "1.0.0")
	if err := os.Rename(plugin, filepath.Join(t.TempDir(), "uninstalled")); err != nil {
		t.Fatal(err)
	}
	if err := refreshMachineStatus(); err != nil {
		t.Fatal(err)
	}
	out = inspectMachine(time.Now())
	if out.Status == "local_checked" || out.NextAction.Code != "install_plugin" || out.LastCheck.Checked != 0 {
		t.Fatalf("empty check: %+v", out)
	}
}

func TestLocalStatusGivesExpiredCatalogToPublisherBeforeFirstCheck(t *testing.T) {
	localStatusFixture(t)
	subs, err := loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := readSnapshotOnly(subs[0], trusted, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := inspectMachine(snapshot.ValidUntil.Add(time.Second))
	if out.Status == "local_checked" || out.NextAction.Code != "renew_catalog" || out.NextAction.Actor != "publisher" || strings.Contains(out.NextAction.Detail, "skillctl connect") {
		t.Fatalf("expired local catalog: %+v", out)
	}
	// The catalog has not been changed or extended just to make status green.
	if _, err := readSnapshotOnly(subs[0], trusted, snapshot.ValidUntil.Add(time.Second)); err == nil || !strings.Contains(err.Error(), catalog.ErrExpired.Error()) {
		t.Fatalf("expiry bypassed: %v", err)
	}
}
