package main

import (
	"strings"
	"testing"
)

func TestSkillNameIsReadFromThePayload(t *testing.T) {
	cases := map[string]string{
		`{"tool_name":"Skill","tool_input":{"skill":"deploy-runbook"}}`: "deploy-runbook",
		// Plugin skills arrive namespaced; a catalog publishes the bare name that SKILL.md
		// declares, so the prefix has to come off or every plugin skill reads as unmanaged.
		`{"tool_name":"Skill","tool_input":{"skill":"acme:deploy-runbook"}}`: "deploy-runbook",
		// Anything unparseable or unrelated yields no name, and no name means no opinion.
		`{"tool_name":"Bash","tool_input":{"command":"ls"}}`: "",
		`{"tool_name":"Skill","tool_input":{}}`:              "",
		`not json at all`:                                    "",
		``:                                                   "",
	}
	for payload, want := range cases {
		if got := skillFromPayload(strings.NewReader(payload)); got != want {
			t.Errorf("skillFromPayload(%q) = %q, want %q", payload, got, want)
		}
	}
}

// A hook on the critical path of every skill invocation must not be able to hang on a
// pathological payload.
func TestAHugePayloadIsBounded(t *testing.T) {
	huge := `{"tool_name":"Skill","tool_input":{"skill":"` + strings.Repeat("a", 4<<20) + `"}}`
	if got := skillFromPayload(strings.NewReader(huge)); got != "" {
		t.Fatalf("an oversized payload must be truncated and rejected, got %d bytes", len(got))
	}
}

// A machine that follows no catalog manages nothing, so the hook has no business having an
// opinion about any skill on it.
func TestAnUnmanagedMachineAllowsEverything(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	if code := runHookPreSkill(nil); code != exitClean {
		t.Fatalf("exit = %d; an unmanaged machine must not refuse anything", code)
	}
}
