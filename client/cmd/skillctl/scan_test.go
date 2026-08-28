package main

import "testing"

// The gate acts on the scanner's own recommendation rather than re-deriving a threshold
// from its score. A tool that invents its own cutoff eventually disagrees with the report
// it prints, and the person reading both has no way to tell which one to believe.
func TestOnlyTheScannersOwnRefusalBlocks(t *testing.T) {
	for recommendation, blocks := range map[string]bool{
		"DO_NOT_INSTALL": true,
		"CAUTION":        false,
		"SAFE":           false,
	} {
		if got := (scanVerdict{Recommendation: recommendation}).Blocks(); got != blocks {
			t.Errorf("%s: blocks=%v, want %v", recommendation, got, blocks)
		}
	}
}

// A report is the scanner's answer; a report that will not parse is no answer, and the
// difference has to survive into the caller, which must never read silence as a pass.
func TestAReportWithoutARecommendationIsNotAPass(t *testing.T) {
	if _, err := parseScanReport([]byte(`{"risk_assessment":{"score":0}}`)); err == nil {
		t.Fatal("a report with no recommendation must be an error, not an implicit SAFE")
	}
	if _, err := parseScanReport([]byte(`not json`)); err == nil {
		t.Fatal("an unreadable report must be an error")
	}
}

// Fields this build does not know must not break the gate: SkillSpector ships rules and
// schema changes on its own cadence, and a gate that fails closed on an unknown key is a
// gate publishers turn off.
func TestAReportWithUnknownFieldsStillParses(t *testing.T) {
	verdict, err := parseScanReport([]byte(`{
	  "risk_assessment": {"score": 64, "recommendation": "DO_NOT_INSTALL", "future": "?"},
	  "metadata": {"llm_available": false, "something_new": 1},
	  "issues": [
	    {"severity":"HIGH","category":"Tool Misuse","finding":"subprocess.Popen(",
	     "location":{"file":"scripts/with_server.py","start_line":69},"unknown":true},
	    {"severity":"MEDIUM","category":"policy","explanation":"no declared permissions",
	     "location":{"file":"SKILL.md","start_line":1}}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Blocks() || verdict.Score != 64 {
		t.Fatalf("verdict lost its meaning: %+v", verdict)
	}
	if verdict.Severities["HIGH"] != 1 || verdict.Severities["MEDIUM"] != 1 {
		t.Fatalf("severity counts wrong: %v", verdict.Severities)
	}
	if verdict.LLMUsed {
		t.Fatal("a static-only scan must not report itself as semantic")
	}
	// An issue with no finding text falls back to its explanation: a finding printed
	// blank is one an operator cannot act on.
	if verdict.Findings[1].Detail != "no declared permissions" {
		t.Fatalf("explanation not used as detail: %q", verdict.Findings[1].Detail)
	}
}
