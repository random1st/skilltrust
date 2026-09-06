package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/internal/marketplace"
)

func TestDoctorKeepsSavedChangesDiscoverableAfterACleanCheck(t *testing.T) {
	_, client := localStatusFixture(t)
	if code := tamperDemoPlugin(client); code != exitClean {
		t.Fatal(code)
	}
	check, code := RunManagedCheck(client, ManagedCheckOptions{Restore: true, Offline: true})
	if code != exitClean || len(check.Results) != 1 || check.Results[0].Outcome != marketplace.OutcomeRestored {
		t.Fatalf("fixture did not restore the changed plugin: %+v, %d", check, code)
	}
	saved := check.Results[0].Quarantine
	for i := 0; i < 2; i++ {
		out, code := doctorResult(t, runDoctor, "--json")
		if code != exitFindings || out.LastCheck == nil || out.LastCheck.Checked != 1 || out.LastCheck.Changed != 0 ||
			len(out.SavedChanges) != 1 || out.SavedChanges[0].Path != saved || out.NextAction.Code != "review_saved_change" {
			t.Fatalf("a clean check hid the saved change: %+v, %d", out, code)
		}
		text := capture(t, func() { code = runDiff(out.NextCommand[2:]) })
		if code != exitFindings || !strings.Contains(text, strings.TrimSpace(demoTamper)) || !strings.Contains(text, "--quarantine-digest") {
			t.Fatalf("doctor's exact next command did not expose the saved payload: %s (exit %d)", text, code)
		}
		if _, err := os.Stat(saved); err != nil {
			t.Fatal("review consumed the saved change")
		}
	}
}

func TestDoctorRejectsSavedChangesWithAnUnknownCacheLayout(t *testing.T) {
	_, err := savedChangeTarget(marketplace.PendingQuarantine{
		Path: "/saved/runbook", Plugin: "runbook", Installed: "/unrelated/market/runbook/1.0.0",
	})
	if err == nil {
		t.Fatal("doctor guessed a client for an unrelated saved target")
	}
}

func TestDoctorCanReviewASavedChangeAfterAPublisherUpgrade(t *testing.T) {
	repository, client := localStatusFixture(t)
	capture(t, func() {
		if code := tamperDemoPlugin(client); code != exitClean {
			t.Fatal(code)
		}
	})
	check, code := RunManagedCheck(client, ManagedCheckOptions{Restore: true, Offline: true})
	if code != exitClean || len(check.Results) != 1 || check.Results[0].Outcome != marketplace.OutcomeRestored {
		t.Fatalf("fixture restore: %+v, %d", check, code)
	}
	manifest := filepath.Join(repository, ".claude-plugin", "marketplace.json")
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, bytes.ReplaceAll(body, []byte("1.0.0"), []byte("2.0.0")), 0o644); err != nil {
		t.Fatal(err)
	}
	capture(t, func() {
		if code := runMarketplaceSign([]string{repository}); code != exitClean {
			t.Fatalf("sign upgraded fixture: %d", code)
		}
	})
	if err := demoGit(repository, "add", ".claude-plugin/marketplace.json", CatalogFileName); err != nil {
		t.Fatal(err)
	}
	if err := demoGit(repository, "commit", "--quiet", "-m", "publish version two"); err != nil {
		t.Fatal(err)
	}
	copyTree(t, marketplace.InstalledPath(client, "acme", "deploy-runbook", "2.0.0"), filepath.Join(repository, "plugins", "deploy-runbook"))
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || len(out.SavedChanges) != 1 || out.LastCheck == nil || out.LastCheck.Checked != 1 || out.LastCheck.Changed != 0 {
		t.Fatalf("upgraded fixture verdict: %+v, %d", out, code)
	}
	text := capture(t, func() { code = runDiff(out.SavedChanges[0].NextCommand[2:]) })
	if code != exitFindings || !strings.Contains(text, strings.TrimSpace(demoTamper)) || !strings.Contains(text, "older published version") {
		t.Fatalf("saved v1 cannot be compared with installed v2: %s (exit %d)", text, code)
	}
	if strings.Contains(text, "Run: skillctl adopt") || strings.Contains(text, "--quarantine-digest") {
		t.Fatalf("obsolete v1 edit was offered as a v2 adoption: %s", text)
	}
}
