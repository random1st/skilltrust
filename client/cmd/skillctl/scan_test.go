package main

import (
	"os"
	"strings"
	"testing"
)

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

// The report's own llm_available flag reads false against Bedrock while the scanner is
// making Bedrock calls and being billed for them. Believing it printed "static analysis
// only" over a scan that had just spent money — an understatement, but the same class of
// error as an overstatement: the line did not describe what happened. Tokens accounted
// for are the one claim about this that cannot be wrong.
func TestTheSemanticPassIsCountedFromTokensNotAFlag(t *testing.T) {
	body := []byte(`{
	  "risk_assessment": {"score": 58, "recommendation": "CAUTION"},
	  "metadata": {
	    "llm_available": false,
	    "inference_usage": [
	      {"prompt_tokens": 2390, "completion_tokens": 196},
	      {"prompt_tokens": 11002, "completion_tokens": 935}
	    ]
	  },
	  "issues": []
	}`)
	verdict, err := parseScanReport(body)
	if err != nil {
		t.Fatalf("the report must parse: %v", err)
	}
	if !verdict.LLMUsed {
		t.Error("a scan that spent tokens ran the semantic pass, whatever the flag says")
	}
	if verdict.InputTokens != 13392 || verdict.OutputTokens != 1131 {
		t.Errorf("tokens must be summed across calls, got %d in and %d out",
			verdict.InputTokens, verdict.OutputTokens)
	}
}

// A static-only scan must not claim the deeper pass ran, which is the failure this guards
// from the other side.
func TestAStaticScanClaimsNoSemanticPass(t *testing.T) {
	verdict, err := parseScanReport([]byte(
		`{"risk_assessment": {"score": 0, "recommendation": "SAFE"}, "metadata": {}, "issues": []}`))
	if err != nil {
		t.Fatalf("the report must parse: %v", err)
	}
	if verdict.LLMUsed || verdict.InputTokens != 0 {
		t.Error("a scan with no model calls must not report a semantic pass")
	}
}

// The budgets exist because the scanner has no metadata for Nova, and a wrong budget does
// not fail loudly: every semantic call is rejected, the scan still succeeds, and the
// rejections surface as findings against the skill. A skill scoring worse because of our
// configuration is the worst available outcome, so the file must stay parseable and must
// keep every cap under its model's documented limit — Bedrock refuses a request equal to
// the limit, not merely one above it.
func TestTheModelBudgetsAreUsableAndUnderEveryCap(t *testing.T) {
	if len(modelBudgets) == 0 {
		t.Fatal("the embedded budgets are empty; the semantic pass would fail on every call")
	}
	text := string(modelBudgets)
	for _, model := range []string{"us.amazon.nova-lite-v1:0", "us.amazon.nova-micro-v1:0",
		"us.amazon.nova-pro-v1:0", "us.amazon.nova-2-lite-v1:0"} {
		if !strings.Contains(text, model) {
			t.Errorf("no budget for %s, so a scan with it reports our own failures as findings", model)
		}
	}
	for _, forbidden := range []string{"max_output_tokens: 10000", "max_output_tokens: 65535",
		"max_output_tokens: 65536"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("%q is at or above a documented cap; Bedrock rejects the request", forbidden)
		}
	}
	path, err := writeModelBudgets()
	if err != nil {
		t.Fatalf("the budgets must be writable for the scanner to read: %v", err)
	}
	defer os.Remove(path)
	written, err := os.ReadFile(path)
	if err != nil || string(written) != text {
		t.Fatal("the file handed to the scanner must be the budgets themselves")
	}
}
