package lint

import (
	"strings"
	"testing"
)

// A machine keeps skills in several directories and the agent reads all of them. The
// scanner read one and mentioned the rest in a line on stderr that read as a footnote —
// on the machine this was found on, that was 99 skills reported out of 109.
func TestEveryRootIsCoveredAndSummarisedOnce(t *testing.T) {
	run := Reports{Reports: []*Report{
		{Root: "/a", Skills: []SkillReport{
			{Name: "one", Findings: []Finding{{Severity: SeverityHigh, Rule: "r", Path: "one"}}},
		}},
		{Root: "/b", Skills: []SkillReport{
			{Name: "two", Findings: []Finding{{Severity: SeverityLow, Rule: "r", Path: "two"}}},
		}},
	}}

	var out strings.Builder
	if err := RenderTextAll(&out, run); err != nil {
		t.Fatal(err)
	}
	body := out.String()

	for _, expected := range []string{"/a", "/b", "one", "two"} {
		if !strings.Contains(body, expected) {
			t.Errorf("%q is missing from a report over both roots:\n%s", expected, body)
		}
	}
	// One summary for the run. Four totals to add up by hand is how a reader takes the
	// first one and stops.
	if got := strings.Count(body, " skills · "); got != 1 {
		t.Errorf("summary lines = %d, want exactly 1:\n%s", got, body)
	}
	if !strings.Contains(body, "2 skills · 1 high · 0 medium · 1 low") {
		t.Errorf("the totals must cover every root:\n%s", body)
	}
	if !strings.Contains(body, "across 2 directories") {
		t.Errorf("the reader must be told how many directories that covered:\n%s", body)
	}
}

// The display filter shortens the list and must never shorten the verdict. A tool whose
// exit code could be quietened by asking for less output reports what you asked to hear.
func TestTheSeverityFloorHidesFindingsButNeverCounts(t *testing.T) {
	run := Reports{
		ShownAtOrAbove: SeverityHigh,
		Reports: []*Report{{Root: "/a", Skills: []SkillReport{{Name: "one", Findings: []Finding{
			{Severity: SeverityHigh, Rule: "loud", Path: "one"},
			{Severity: SeverityLow, Rule: "quiet", Path: "one"},
		}}}}},
	}

	var out strings.Builder
	if err := RenderTextAll(&out, run); err != nil {
		t.Fatal(err)
	}
	body := out.String()

	if strings.Contains(body, "quiet") {
		t.Errorf("a finding below the floor must not be listed:\n%s", body)
	}
	if !strings.Contains(body, "loud") {
		t.Errorf("a finding at the floor must be listed:\n%s", body)
	}
	// Counts are of everything found, and the gap between them and the list is said out
	// loud — otherwise the two disagree and the reader trusts the shorter one.
	if !strings.Contains(body, "1 high · 0 medium · 1 low") {
		t.Errorf("the counts must ignore the filter:\n%s", body)
	}
	if !strings.Contains(body, "counted but not listed") {
		t.Errorf("the hidden findings must be admitted to:\n%s", body)
	}
	if run.AtOrAbove(SeverityLow) != 2 {
		t.Error("--fail-on must read every finding, filtered or not")
	}
}

// SARIF is read by code scanning, not by a person with a context window. Dropping findings
// from the artefact an audit reads would be the worst place in this tool to save space.
func TestTheSeverityFloorDoesNotReachSARIF(t *testing.T) {
	run := Reports{
		ShownAtOrAbove: SeverityHigh,
		Reports: []*Report{{Root: "/a", Skills: []SkillReport{{Name: "one", Findings: []Finding{
			{Severity: SeverityLow, Rule: "quiet", Path: "one"},
		}}}}},
	}

	var out strings.Builder
	if err := RenderSARIFAll(&out, run, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "quiet") {
		t.Errorf("SARIF must carry every finding:\n%s", out.String())
	}
}
