package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Codex CLI keeps its hooks in a file that already has other people's hooks in it. Merging
// into it must leave every one of them alone.
//
// This is the failure that would end the integration on contact: a machine where the hook
// file carries a circuit breaker, a formatter and an audit logger, and installing skillctl
// silently replaces them with one entry. The client keeps working, so nobody notices until
// the thing that was dropped was needed.
func TestInstallingIntoCodexKeepsHooksSomebodyElsePutThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	existing := `{"hooks":{
      "PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"audit-logger"}]}],
      "SessionStart":[{"hooks":[{"type":"command","command":"someone-elses-setup"}]}]
    }}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	added, err := applyClaudeHooks(path, codexHooks("/usr/local/bin/skillctl"))
	if err != nil || len(added) != 1 {
		t.Fatalf("added = %d, err = %v", len(added), err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, survivor := range []string{"audit-logger", "someone-elses-setup"} {
		if !strings.Contains(text, survivor) {
			t.Errorf("installing removed %q, which this tool did not put there:\n%s", survivor, text)
		}
	}
	if !strings.Contains(text, "hook session-start --agent codex") {
		t.Errorf("the codex hook must target the codex home:\n%s", text)
	}

	// And it is reversible, leaving the other entries behind.
	removed, err := removeClaudeHooks(path, "skillctl")
	if err != nil || removed != 1 {
		t.Fatalf("removed = %d, err = %v", removed, err)
	}
	raw, _ = os.ReadFile(path)
	for _, survivor := range []string{"audit-logger", "someone-elses-setup"} {
		if !strings.Contains(string(raw), survivor) {
			t.Errorf("uninstalling took %q with it", survivor)
		}
	}
}

// The first install on a machine has no hook file to merge into. Codex keeps its hooks in
// a dedicated hooks.json that simply does not exist until something writes one, so the
// ordinary first run used to fail with "cannot read … no such file or directory" against a
// client that was working fine.
func TestTheFirstInstallWorksWithNoHookFileYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh", "hooks.json")

	added, err := applyClaudeHooks(path, codexHooks("/usr/local/bin/skillctl"))
	if err != nil {
		t.Fatalf("a first install must create the file: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("added = %d, want 1", len(added))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Hooks map[string][]any `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("what was written is not valid JSON: %v", err)
	}
	if len(document.Hooks["SessionStart"]) != 1 {
		t.Fatalf("the hook did not land: %s", raw)
	}
	// Nothing existed, so nothing was backed up — and the caller must not be offered a
	// file to copy back that was never written.
	if _, err := os.Stat(path + ".skillctl-backup"); err == nil {
		t.Error("a first install has nothing to back up and must not invent a backup")
	}
}

// Each client is configured in its own file. Writing Codex's hooks into Claude's settings
// would be a change nobody reads and a check that never runs.
func TestEachClientIsConfiguredWhereItReads(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")

	claude, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	codex, err := lookupAgent("codex")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(claude.HookConfigPath()) != "settings.json" {
		t.Errorf("claude reads hooks from settings.json, got %s", claude.HookConfigPath())
	}
	if filepath.Base(codex.HookConfigPath()) != "hooks.json" {
		t.Errorf("codex reads hooks from hooks.json, got %s", codex.HookConfigPath())
	}
	if claude.HookConfigPath() == codex.HookConfigPath() {
		t.Fatal("two clients must not share one configuration file")
	}
}

// An unknown client is refused by name rather than silently treated as the default: a
// typo that installs a hook for the wrong agent produces a machine that reports nothing
// and looks configured.
func TestAnUnknownClientIsRefusedAndNamesWhatExists(t *testing.T) {
	_, err := lookupAgent("claude-code")
	if err == nil {
		t.Fatal("an unsupported client must be refused, not defaulted")
	}
	for _, expected := range []string{"claude-code", "claude", "codex", "cursor", "antigravity"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("the refusal must mention %q, got %v", expected, err)
		}
	}
}

// The home an explicit path names always wins. Checking a machine that is not this one —
// an image being built, a home restored from backup — must not require that client to be
// installed here.
func TestAnExplicitHomeOutranksTheAgentsOwn(t *testing.T) {
	home, err := resolveAgentHome("codex", "/mnt/image/root/.codex")
	if err != nil {
		t.Fatal(err)
	}
	if home != "/mnt/image/root/.codex" {
		t.Fatalf("home = %s, want the explicit path", home)
	}
	if _, err := resolveAgentHome("nonsense", ""); err == nil {
		t.Error("an unknown agent with no explicit home must be an error")
	}
}

// Codex 0.149.1 reads loose skills from ~/.codex/skills as well as the cross-client
// ~/.agents/skills. A checker that only knew about ~/.claude/skills would report on a
// different machine than the agent is running on.
func TestSkillRootsCoverEveryClientsOwnDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Windows reads USERPROFILE, not HOME: setting only HOME left this test looking at the
	// real user's home, where it passed or failed for reasons that had nothing to do with
	// the code under test.
	t.Setenv("USERPROFILE", home)
	for _, dir := range []string{
		filepath.Join(".agents", "skills"),
		filepath.Join(".claude", "skills"),
		filepath.Join(".codex", "skills"),
		filepath.Join(".cursor", "skills"),
		filepath.Join(".gemini", "config", "skills"),
	} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	found := strings.Join(skillRoots(), " ")
	for _, expected := range []string{
		".agents/skills", ".claude/skills", ".codex/skills", ".cursor/skills",
		".gemini/config/skills",
	} {
		if !strings.Contains(filepath.ToSlash(found), expected) {
			t.Errorf("%s is not scanned; roots were %s", expected, found)
		}
	}
}

// Cursor installs nothing from a marketplace — verified against cursor-agent 2026.01.28,
// whose bundle has no plugins/cache path and no marketplace of any kind. So reconciling has
// nothing to act on, and the entry that would have run at its session start must not exist:
// a hook that walks an empty tree prints the same nothing as a machine where everything
// matched, and the two would be indistinguishable to the person relying on it.
//
// This is the same refusal the Codex work made about a PreToolUse matcher that would never
// fire, and it is worth a test rather than a comment because the pressure to add the entry
// comes back every time somebody notices Cursor does have a sessionStart hook. It does. What
// it does not have is anything for that hook to check.
func TestCursorIsNotGivenAHookItHasNothingToCheckWith(t *testing.T) {
	cursor, err := lookupAgent("cursor")
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Managed {
		t.Error("Cursor has no <home>/plugins/cache; claiming otherwise makes " +
			"reconciling walk a tree that is not there")
	}
	if cursor.Hooks != nil {
		t.Fatal("Cursor has no plugin cache, so an entry at any of its moments would be " +
			"a check that can never report anything")
	}

	// And whoever asks for one is told why, in terms of their client rather than ours.
	// "Nothing to install" alone reads as a bug in this tool.
	for _, expected := range []string{"marketplace", "skillctl lint", ".cursor/skills"} {
		if !strings.Contains(cursor.NoHooksBecause, expected) {
			t.Errorf("the explanation must mention %q, got:\n%s", expected, cursor.NoHooksBecause)
		}
	}
}

// Every agent without hooks owes an explanation, and every agent with them owes none. The
// pairing is what stops a future client being added with Hooks left nil by oversight and
// printing an empty line where a reason belongs.
func TestAnAgentWithNoHooksSaysWhy(t *testing.T) {
	for _, known := range agents {
		if known.Hooks == nil && known.NoHooksBecause == "" {
			t.Errorf("%s has no hooks and does not say why", known.Name)
		}
		if known.Hooks != nil && known.NoHooksBecause != "" {
			t.Errorf("%s has hooks; explaining their absence would be false", known.Name)
		}
		if !known.Managed && known.Hooks != nil {
			t.Errorf("%s installs nothing from a marketplace, so its hook would "+
				"reconcile an empty tree", known.Name)
		}
	}
}

// Antigravity CLI lets a repository register skills anywhere. `.agents/skills.json` names
// directories with `entries[].path`, and that is the documented way a team shares them — so
// the set of directories the agent reads is a property of the machine, not of our table.
//
// This is the failure the scanner already made once with a different cause: reporting on one
// root while others existed, and being believed. A team whose skills live in
// tools/agents/skills would have been told their machine was clean by a command that never
// opened the directory.
func TestSkillsRegisteredThroughAntigravityConfigAreFound(t *testing.T) {
	base := t.TempDir()
	elsewhere := filepath.Join(base, "tools", "agents", "skills")
	shared := filepath.Join(base, "vendor", "shared-skills")
	for _, dir := range []string{elsewhere, shared, filepath.Join(base, ".agents")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A config that inherits another. Inheritance is followed because a shared config is
	// how an organisation distributes these paths, so stopping at the first file would miss
	// exactly the machines carrying the most skills.
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(base, "team-skills.json"),
		`{"entries":[{"path":"vendor/shared-skills"}]}`)
	write(filepath.Join(base, ".agents", "skills.json"), `{
	  "inherits": [{"path": "team-skills.json"}],
	  "entries": [
	    {"path": "tools/agents/skills"},
	    {"path": "tools/agents/does-not-exist"}
	  ]
	}`)

	found := antigravityRoots(base)
	for _, expected := range []string{elsewhere, shared} {
		if !slices.Contains(found, expected) {
			t.Errorf("%s is registered but was not found; got %v", expected, found)
		}
	}
	// A path that names nothing must not be reported as a directory that was scanned.
	for _, root := range found {
		if strings.Contains(root, "does-not-exist") {
			t.Errorf("a path pointing at nothing was returned as a root: %s", root)
		}
	}
}

// A skills.json that inherits itself must not hang the command that reads it, and one that
// is not valid JSON must cost nothing. Both run at session start, where a hang is
// indistinguishable from a broken client and a crash gets the tool removed.
func TestABrokenAntigravityConfigCostsNothing(t *testing.T) {
	for name, body := range map[string]string{
		"inherits itself":  `{"inherits":[{"path":".agents/skills.json"}],"entries":[]}`,
		"not valid JSON":   `{"entries": [`,
		"empty document":   `{}`,
		"paths are absent": `{"entries":[{"path":""}],"inherits":[{"path":""}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			if err := os.MkdirAll(filepath.Join(base, ".agents"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(base, ".agents", "skills.json"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			// The assertion is that this returns at all.
			if roots := antigravityRoots(base); len(roots) != 0 {
				t.Errorf("a config naming nothing produced roots: %v", roots)
			}
		})
	}
}

// The three path rules Antigravity documents, each of which a naive filepath.Join gets
// wrong in a different way.
func TestAntigravityPathsResolveTheWayItDocuments(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory here")
	}
	// The absolute case is spelled per platform: "/opt/skills" is not absolute on Windows,
	// where filepath.IsAbs wants a drive letter, so asserting it there tested the test.
	absolute := "/opt/skills"
	workspace := "/repo"
	if runtime.GOOS == "windows" {
		absolute = `C:\opt\skills`
		workspace = `C:\repo`
	}
	cases := map[string]struct{ given, want string }{
		"absolute stays absolute": {absolute, absolute},
		"tilde is the home":       {"~/personal-skills", filepath.Join(home, "personal-skills")},
		"bare is workspace":       {"tools/skills", filepath.Join(workspace, "tools", "skills")},
	}
	for name, one := range cases {
		t.Run(name, func(t *testing.T) {
			if got := resolveConfigPath(one.given, workspace); got != one.want {
				t.Errorf("resolveConfigPath(%q) = %q, want %q", one.given, got, one.want)
			}
		})
	}
}

// Codex asks before it runs a hook it has not seen: it keeps a trusted_hash per hook in
// config.toml and reviews anything new. Writing the entry is therefore not the end of the
// job, and an installer that said "installed" and stopped would leave somebody believing a
// hook protects them while it sits untrusted — the exact "looks configured, is not
// running" state this project exists to prevent.
func TestInstallingForCodexSaysWhatIsStillOutstanding(t *testing.T) {
	codex, err := lookupAgent("codex")
	if err != nil {
		t.Fatal(err)
	}
	if codex.AfterInstall == "" {
		t.Fatal("codex reviews hooks before running them; the installer must say so")
	}
	for _, expected := range []string{"trust", "until you do"} {
		if !strings.Contains(strings.ToLower(codex.AfterInstall), expected) {
			t.Errorf("the note must make the outstanding step plain; %q is missing from:\n%s",
				expected, codex.AfterInstall)
		}
	}
	// And it must not teach the shortcut that turns the review off for everything.
	if !strings.Contains(codex.AfterInstall, "rather than with --dangerously-bypass-hook-trust") {
		t.Error("the note must steer towards approving the hook, not disabling the review")
	}

	claude, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	if claude.AfterInstall != "" {
		t.Error("Claude Code runs what is in settings.json; inventing a step would be noise")
	}
}

// The hook a client is given must be one that client actually offers. Codex does not route
// a skill through a tool call — it lists them in the developer message at session start —
// so a PreToolUse entry there would be a hook that never fires and a promise that is never
// kept.
func TestCodexIsOnlyGivenHooksItHas(t *testing.T) {
	for _, spec := range codexHooks("/usr/local/bin/skillctl") {
		if spec.Event != "SessionStart" {
			t.Errorf("codex was given a %s hook; it has no moment that means "+
				"\"a skill is about to load\"", spec.Event)
		}
	}

	// And the entry it does get must be shaped the way Codex reads it: the same JSON as
	// Claude Code, which is why one merge serves both.
	encoded, err := json.Marshal(codexHooks("/usr/local/bin/skillctl")[0].entry())
	if err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Hooks []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(encoded, &entry); err != nil {
		t.Fatal(err)
	}
	if len(entry.Hooks) != 1 || entry.Hooks[0].Type != "command" {
		t.Fatalf("codex expects a command handler, got %s", encoded)
	}
}
