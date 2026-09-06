package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
)

func TestStatuslineNeverCallsEmptyOrStaleEvidencePassed(t *testing.T) {
	now := time.Now().UTC()
	healthy := report.CheckResult{Complete: true, Checked: 1, CheckedAt: now.Add(-time.Minute), FreshUntil: now.Add(time.Hour)}
	for _, name := range []string{"missing", "empty", "stale", "partial", "changed", "unapproved", "errors", "unverified status", "saved edit", "broken provenance"} {
		t.Run(name, func(t *testing.T) {
			check := healthy
			status := machineStatus{Status: "local_checked", LastCheck: &check}
			pending := 0
			var quarantineErr error
			switch name {
			case "missing":
				status.LastCheck = nil
			case "empty":
				check.Checked = 0
			case "stale":
				check.FreshUntil = now
			case "partial":
				check.Complete = false
			case "changed":
				check.Changed = 1
			case "unapproved":
				check.Unapproved = 1
			case "errors":
				check.Errors = 1
			case "unverified status":
				status.Status = "needs_attention"
			case "saved edit":
				pending = 1
			case "broken provenance":
				quarantineErr = fmt.Errorf("bad provenance")
			}
			marker := statuslineText(status, pending, quarantineErr, now)
			if strings.Contains(marker, "passed") || !strings.Contains(marker, "doctor") {
				t.Fatalf("invalid evidence looked passed: %s", marker)
			}
		})
	}
	if marker := statuslineText(machineStatus{Status: "local_checked", LastCheck: &healthy}, 0, nil, now); marker != "Axela: last managed check passed" {
		t.Fatalf("healthy cached evidence marker = %q", marker)
	}
}

func TestStatuslineColdReadCreatesNoKeysOrSettings(t *testing.T) {
	state := filepath.Join(t.TempDir(), "not-created")
	t.Setenv("SKILLTRUST_HOME", state)
	client := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", client)
	settings := filepath.Join(client, "settings.json")
	before := []byte(`{"statusLine":{"type":"command","command":"company-status"},"allowManagedHooksOnly":true}`)
	if err := os.WriteFile(settings, before, 0o600); err != nil {
		t.Fatal(err)
	}
	output, code := captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || !strings.Contains(output, "unchecked") || !strings.Contains(output, "doctor") {
		t.Fatalf("cold marker = %d %q", code, output)
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatalf("read-only marker created state or keys: %v", err)
	}
	after, err := os.ReadFile(settings)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("marker overwrote an existing company status line: %v", err)
	}
}

func TestStatuslineUsesVerifiedCachedReportsAndKeepsRecoveryWarning(t *testing.T) {
	_, client := localStatusFixture(t)
	managed, code := RunManagedCheck(client, ManagedCheckOptions{Offline: true})
	if code != exitClean {
		t.Fatalf("fixture check: %d", code)
	}
	if _, err := recordCurrentChecks(0, managedCurrentCheck(managed)); err != nil {
		t.Fatal(err)
	}
	output, code := captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || !strings.Contains(output, "last managed check passed") {
		t.Fatalf("valid cached check was not recognized: %d %q", code, output)
	}
	before, err := os.ReadFile(latestCheckPath(CheckScopeManaged))
	if err != nil {
		t.Fatal(err)
	}
	installed := marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0")
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("another published copy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved, err := marketplace.Restore(installed, source, quarantineRoot(), "deploy-runbook", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	output, code = captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || !strings.Contains(output, "edits saved (1)") {
		t.Fatalf("saved edit lost behind cached clean report: %d %q", code, output)
	}
	after, err := os.ReadFile(latestCheckPath(CheckScopeManaged))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("statusline refreshed or rewrote the cached check: %v", err)
	}
	if err := marketplace.Reclaim(saved, installed); err != nil {
		t.Fatal(err)
	}
	output, code = captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || strings.Contains(output, "edits saved") {
		t.Fatalf("consumed copy still marks saved edits: %d %q", code, output)
	}
	if err := os.WriteFile(latestCheckPath(CheckScopeManaged), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, code = captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || strings.Contains(output, "passed") {
		t.Fatalf("malformed signed report looked passed: %d %q", code, output)
	}
}

func TestStatuslineCannotHideLooseSkillFailuresBehindManagedSuccess(t *testing.T) {
	_, client := localStatusFixture(t)
	managed, code := RunManagedCheck(client, ManagedCheckOptions{Offline: true})
	if code != exitClean {
		t.Fatalf("fixture check: %d", code)
	}
	now := time.Now().UTC()
	if _, err := recordCurrentChecks(0, managedCurrentCheck(managed), CurrentCheck{
		Scope: CheckScopeApprovedSkills, CheckedAt: now, FreshUntil: now.Add(time.Hour),
		Complete: true, Checked: 2, Changed: 1,
	}); err != nil {
		t.Fatal(err)
	}
	output, code := captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || !strings.Contains(output, "changed (1)") || strings.Contains(output, "passed") {
		t.Fatalf("managed report hid changed loose skill: %d %q", code, output)
	}
	if err := os.WriteFile(latestCheckPath(CheckScopeApprovedSkills), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, code = captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || !strings.Contains(output, "needs attention") || strings.Contains(output, "passed") {
		t.Fatalf("managed report hid malformed loose skill report: %d %q", code, output)
	}
}
