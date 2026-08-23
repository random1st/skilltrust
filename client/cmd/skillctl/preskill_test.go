package main

import (
	"strings"
	"testing"
)

// Claude Code namespaces every plugin skill as plugin:skill, so the prefix identifies the
// plugin and the absence of one identifies a skill this tool has no business touching. That
// distinction is the boundary of the whole product, read off a single string.
func TestThePluginIsReadFromTheSkillName(t *testing.T) {
	cases := map[string]string{
		`{"tool_name":"Skill","tool_input":{"skill":"acme-devtools:deploy"}}`: "acme-devtools",
		`{"tool_name":"Skill","tool_input":{"skill":"s5d:s5d"}}`:              "s5d",
		// Unnamespaced: a personal or project skill. Not ours.
		`{"tool_name":"Skill","tool_input":{"skill":"my-own-notes"}}`: "",
		// Unrelated or unreadable payloads yield no opinion at all.
		`{"tool_name":"Bash","tool_input":{"command":"ls"}}`: "",
		`{"tool_name":"Skill","tool_input":{}}`:              "",
		`not json at all`:                                    "",
		``:                                                   "",
		// A trailing colon names no plugin.
		`{"tool_name":"Skill","tool_input":{"skill":":orphan"}}`: "",
	}
	for payload, want := range cases {
		if got := pluginFromPayload(strings.NewReader(payload)); got != want {
			t.Errorf("pluginFromPayload(%q) = %q, want %q", payload, got, want)
		}
	}
}

// A hook on the critical path of every skill invocation must not be able to hang on a
// pathological payload.
func TestAHugePayloadIsBounded(t *testing.T) {
	huge := `{"tool_name":"Skill","tool_input":{"skill":"` + strings.Repeat("a", 4<<20) + `:x"}}`
	if got := pluginFromPayload(strings.NewReader(huge)); got != "" {
		t.Fatalf("an oversized payload must be truncated and rejected, got %d bytes", len(got))
	}
}

// A machine that follows no signed marketplace manages nothing, so the hook has no business
// having an opinion about any skill on it.
func TestAnUnmanagedMachineAllowsEverything(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	if code := runHookPreSkill(nil); code != exitClean {
		t.Fatalf("exit = %d; an unmanaged machine must not refuse anything", code)
	}
}
