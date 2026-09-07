package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/internal/marketplace"
)

func readClaudeHookOutput(t *testing.T, body string) claudeHookOutput {
	t.Helper()
	var out claudeHookOutput
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("not a Claude hook JSON object: %v\n%s", err, body)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("hook mixed JSON and other output: %v\n%s", err, body)
	}
	return out
}

func TestClaudeSessionJSONRestoresAndNamesTheExactSavedCopy(t *testing.T) {
	_, client := localStatusFixture(t)
	installed := marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0")
	published, err := os.ReadFile(filepath.Join(installed, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	capture(t, func() {
		if code := tamperDemoPlugin(client); code != exitClean {
			t.Fatalf("tamper fixture: %d", code)
		}
	})
	edited, err := os.ReadFile(filepath.Join(installed, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := marketplace.DigestInstalled(installed)
	if err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	code := runHookSessionStartForBases([]string{"--claude-json", "--fetch=false", "--claude-home", client}, &output, &diagnostics, []string{t.TempDir()})
	if code != exitClean || diagnostics.Len() != 0 {
		t.Fatalf("hook exit=%d stderr=%q", code, diagnostics.String())
	}
	out := readClaudeHookOutput(t, output.String())
	if out.SystemMessage == "" || out.HookSpecificOutput == nil || out.HookSpecificOutput.HookEventName != "SessionStart" ||
		out.HookSpecificOutput.AdditionalContext != out.SystemMessage {
		t.Fatalf("restoration was not visible to both user and agent: %+v", out)
	}
	saved, ok, err := marketplace.NewestQuarantine(quarantineRoot(), installed, "deploy-runbook")
	if err != nil || !ok {
		t.Fatalf("saved edit missing: %t (%v)", ok, err)
	}
	// Paths may appear in either spelling of the same directory: the hook prints the
	// resolved form, and on Windows the temp directory is handed out as an 8.3 short name
	// (RUNNER~1) that resolves to the long one — like /var and /private/var on macOS.
	spelled := func(path string) bool {
		if strings.Contains(out.SystemMessage, path) {
			return true
		}
		resolved, err := filepath.EvalSymlinks(path)
		return err == nil && strings.Contains(out.SystemMessage, resolved)
	}
	for _, required := range []string{"restored", " diff ", " adopt ", "--marketplace acme", "--claude-home", "--quarantine", "--quarantine-digest", digest} {
		if !strings.Contains(out.SystemMessage, required) {
			t.Errorf("visible warning omits %q:\n%s", required, out.SystemMessage)
		}
	}
	for _, path := range []string{client, saved} {
		if !spelled(path) {
			t.Errorf("visible warning names neither spelling of %q:\n%s", path, out.SystemMessage)
		}
	}
	if body, err := os.ReadFile(filepath.Join(installed, "SKILL.md")); err != nil || !bytes.Equal(body, published) {
		t.Fatalf("published bytes were not restored: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(saved, "SKILL.md")); err != nil || !bytes.Equal(body, edited) {
		t.Fatalf("the warning's saved copy is not the original edit: %v", err)
	}
	output.Reset()
	if code := runHookSessionStartForBases([]string{"--claude-json", "--fetch=false", "--claude-home", client}, &output, &diagnostics, []string{t.TempDir()}); code != exitClean {
		t.Fatalf("second hook exit = %d", code)
	}
	readClaudeHookOutput(t, output.String())
	status, code := captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || !strings.Contains(status, "edits saved (1)") {
		t.Fatalf("a later clean session hid the saved edit: %d %s", code, status)
	}
}

func TestClaudeSessionJSONShowsIncompleteAndMalformedChecks(t *testing.T) {
	for _, damage := range []string{"catalog", "trusted keys", "adoptions"} {
		t.Run(damage, func(t *testing.T) {
			_, client := localStatusFixture(t)
			path := indexPath(Subscription{Name: "acme"})
			if damage == "trusted keys" {
				path = defaultTrustedKeys()
			} else if damage == "adoptions" {
				path = defaultAdoptions()
			}
			if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			var output, diagnostics bytes.Buffer
			if code := runHookSessionStartForBases([]string{"--claude-json", "--fetch=false", "--claude-home", client}, &output, &diagnostics, []string{t.TempDir()}); code != exitClean {
				t.Fatalf("session warning stopped the session: %d", code)
			}
			out := readClaudeHookOutput(t, output.String())
			if out.SystemMessage == "" || diagnostics.Len() != 0 {
				t.Fatalf("malformed state vanished into invisible stderr: %+v stderr=%q", out, diagnostics.String())
			}
			if damage == "catalog" && !strings.Contains(out.SystemMessage, "not checked") {
				t.Fatalf("unusable catalog is presented as checked: %s", out.SystemMessage)
			}
		})
	}
}

func TestClaudeSessionJSONDoesNotPresentAbsentPluginsAsVerified(t *testing.T) {
	_, client := localStatusFixture(t)
	installed := marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0")
	if err := os.RemoveAll(installed); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if code := runHookSessionStartForBases([]string{"--claude-json", "--fetch=false", "--claude-home", client}, &output, &diagnostics, []string{t.TempDir()}); code != exitClean {
		t.Fatalf("session warning exit = %d", code)
	}
	if out := readClaudeHookOutput(t, output.String()); !strings.Contains(out.SystemMessage, "no installed skill was verified") || !strings.Contains(out.SystemMessage, "doctor") {
		t.Fatalf("empty coverage was hidden: %+v", out)
	}
}

func TestClaudeSessionDiscoveryFailureInvalidatesEarlierCachedSuccess(t *testing.T) {
	_, client := localStatusFixture(t)
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, ".agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, ".agents", "skills"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if code := runHookSessionStartForBases([]string{"--claude-json", "--fetch=false", "--claude-home", client}, &output, &diagnostics, []string{base}); code != exitClean {
		t.Fatalf("session warning exit = %d", code)
	}
	if out := readClaudeHookOutput(t, output.String()); !strings.Contains(out.SystemMessage, "local skills could not be checked") {
		t.Fatalf("broken discovery was hidden: %+v", out)
	}
	marker, code := captureStdout(t, func() int { return runStatusline(nil) })
	if code != exitClean || strings.Contains(marker, "passed") || !strings.Contains(marker, "attention") {
		t.Fatalf("a managed success hid failed loose discovery: %d %s", code, marker)
	}
}

func TestClaudePreSkillJSONWarnsOnRestoreAndPreservesDenial(t *testing.T) {
	_, client := localStatusFixture(t)
	payload := `{"tool_name":"Skill","tool_input":{"skill":"deploy-runbook:deploy"}}`
	capture(t, func() { tamperDemoPlugin(client) })
	var output, diagnostics bytes.Buffer
	args := []string{"--claude-json", "--claude-home", client}
	if code := runHookPreSkillTo(args, strings.NewReader(payload), &output, &diagnostics); code != exitClean {
		t.Fatalf("a successful restore was denied: %d", code)
	}
	out := readClaudeHookOutput(t, output.String())
	if diagnostics.Len() != 0 || out.HookSpecificOutput == nil || out.HookSpecificOutput.HookEventName != "PreToolUse" ||
		!strings.Contains(out.SystemMessage, "restored") || !strings.Contains(out.SystemMessage, "--quarantine-digest") {
		t.Fatalf("restoration was invisible or did not name the exact edit: %+v stderr=%q", out, diagnostics.String())
	}
	output.Reset()
	if code := runHookPreSkillTo(args, strings.NewReader(payload), &output, &diagnostics); code != exitClean {
		t.Fatalf("clean check exit = %d", code)
	}
	if out := readClaudeHookOutput(t, output.String()); out.SystemMessage != "" || out.HookSpecificOutput != nil {
		t.Fatalf("a clean check changed normal permissions: %+v", out)
	}
	if err := os.WriteFile(indexPath(Subscription{Name: "acme"}), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if code := runHookPreSkillTo(args, strings.NewReader(payload), &output, &diagnostics); code != exitDeny {
		t.Fatalf("JSON adapter weakened the denial to %d", code)
	}
	if output.Len() != 0 || !strings.Contains(diagnostics.String(), "not loaded") {
		t.Fatalf("deny no longer carries its stderr reason: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
	output.Reset()
	diagnostics.Reset()
	if code := runHookPreSkillTo(append(args, "--permissive"), strings.NewReader(payload), &output, &diagnostics); code != exitClean {
		t.Fatalf("explicit permissive mode changed: %d", code)
	}
	if out := readClaudeHookOutput(t, output.String()); !strings.Contains(out.SystemMessage, "allowed by permissive mode") || strings.Contains(out.SystemMessage, "not loaded") {
		t.Fatalf("permissive warning misdescribes the outcome: %s", out.SystemMessage)
	}
}

func TestClaudeHookWarningEscapesCommandsAndTerminalControls(t *testing.T) {
	home := filepath.Join(t.TempDir(), "client's $(touch BAD); directory")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	result := marketplace.Result{ClientHome: home, Marketplace: "acme", Plugin: "runbook", Installed: "1.0.0", Outcome: marketplace.OutcomeRestored,
		Quarantine: filepath.Join(t.TempDir(), "saved copy's $(touch BAD)"), OnDisk: "sha256:" + strings.Repeat("a", 64)}
	var notice, output bytes.Buffer
	writeQuarantineNotice(&notice, result)
	if !strings.Contains(notice.String(), `'"'"'`) || !strings.Contains(notice.String(), "--quarantine-digest") {
		t.Fatalf("ready command did not escape shell syntax: %s", notice.String())
	}
	notice.WriteString("\nmalicious label: \x1b[2J\u202e hidden")
	if err := writeClaudeHookJSON(&output, "SessionStart", notice.String()); err != nil {
		t.Fatal(err)
	}
	out := readClaudeHookOutput(t, output.String())
	if strings.ContainsAny(out.SystemMessage, "\x1b\u202e") || !strings.Contains(out.SystemMessage, `\u001b`) || !strings.Contains(out.SystemMessage, `\u202e`) {
		t.Fatalf("terminal control data survived in the visible message: %q", out.SystemMessage)
	}
	result.Quarantine += "\nnot a second command"
	notice.Reset()
	writeQuarantineNotice(&notice, result)
	if !strings.Contains(notice.String(), "command arguments (escaped)") || strings.Contains(notice.String(), "\nnot a second command") {
		t.Fatalf("an unprintable path was presented as a copyable command: %q", notice.String())
	}
}

func TestClaudeRevocationStillDeniesInPermissiveMode(t *testing.T) {
	var diagnostics bytes.Buffer
	result := marketplace.Result{Outcome: marketplace.OutcomeRevoked, Marketplace: "acme", Plugin: "runbook"}
	if code := decideTo(result, true, &diagnostics); code != exitDeny || !strings.Contains(diagnostics.String(), "revoked") {
		t.Fatalf("revocation was weakened: %d %q", code, diagnostics.String())
	}
}

func TestClaudeNoticeDoesNotReuseALapsedAdoption(t *testing.T) {
	result := marketplace.Result{ClientHome: t.TempDir(), Marketplace: "acme", Plugin: "runbook", Lapsed: true,
		Quarantine: filepath.Join(t.TempDir(), "saved"), OnDisk: "sha256:" + strings.Repeat("a", 64)}
	var output bytes.Buffer
	writeQuarantineNotice(&output, result)
	if strings.Contains(output.String(), " adopt runbook ") || !strings.Contains(output.String(), "re-apply your change") {
		t.Fatalf("lapsed adoption offered the old approval: %s", output.String())
	}
}
