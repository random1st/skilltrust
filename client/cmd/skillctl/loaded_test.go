package main

import (
	"bytes"
	"strings"
	"testing"
)

// The unit was "a directory with a SKILL.md" because that was the whole product, not
// because it is the whole surface. These are the other things a client reads at the start
// of a session and acts on, and until now nothing named them at all.
func TestLoadedUnitsCoverWhatTheClientsRead(t *testing.T) {
	units := loadedUnits()
	if len(units) == 0 {
		t.Skip("no agent client is configured on this machine")
	}
	kinds := map[string]int{}
	for _, unit := range units {
		kinds[unit.Kind]++
		if unit.Path == "" || unit.Kind == "" {
			t.Errorf("a unit was found with no path or no name: %+v", unit)
		}
	}
	// A subagent is a file the agent will follow with the caller's permissions, and every
	// client in the table has a directory of them.
	if kinds["subagent"] == 0 {
		t.Errorf("no subagents were found, though every client in the table reads a directory of them: %v", kinds)
	}
}

// A count nobody can read is not a finding. The report has to say what the things are and
// that nothing is watching them, because that second half is the whole point.
func TestTheLoadedReportSaysWhatIsNotWatched(t *testing.T) {
	var out bytes.Buffer
	reportLoaded(&out, []loadedUnit{
		{Path: "/home/x/.claude/agents/reviewer.md", Kind: "subagent"},
		{Path: "/home/x/.claude/CLAUDE.md", Kind: "standing instructions"},
	})
	text := out.String()
	for _, want := range []string{"subagent", "standing instructions", "not checked", "No catalog claims them"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}
}

// Nothing to say is said by saying nothing, rather than by an empty heading.
func TestNoLoadedUnitsPrintsNothing(t *testing.T) {
	var out bytes.Buffer
	reportLoaded(&out, nil)
	if out.Len() != 0 {
		t.Errorf("an empty machine produced output:\n%s", out.String())
	}
}
