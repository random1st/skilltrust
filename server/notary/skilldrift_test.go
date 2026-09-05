package notary

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

// A fleet on Cursor or Antigravity installs nothing from a marketplace, so every column on
// this console was structurally empty for them and an organisation would have read that as a
// quiet fleet. This is the one event those machines can ever file about the skills their
// people actually run, and it has to arrive somewhere a person looks.
func TestASkillThatDriftedFromItsApprovalReachesTheConsole(t *testing.T) {
	f := withEventTokens(newFixture(t))
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	org.Machines = attest.NewTrustedKeys(public)
	f.orgs["acme"] = org

	now := time.Now().UTC()
	check, err := report.SignCheck(report.CheckResult{
		Machine: "laptop-7", Scope: "managed", Sequence: 1,
		CheckedAt: now, FreshUntil: now.Add(time.Hour),
		Complete: true, Checked: 3, Unapproved: 1,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	checkBody, _ := json.Marshal(check)
	if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", checkBody); response.StatusCode != http.StatusOK {
		t.Fatalf("check ingest: %s", response.Status)
	}

	// Filed every session until somebody acts on it, which is what a real machine does.
	for session := 0; session < 5; session++ {
		signed, err := report.Sign(report.Event{
			Kind: report.KindSkillChanged, Machine: "laptop-7", Skill: "deploy-runbook",
			Detail: "ops@acme", Signed: "sha256:aaa", Found: "sha256:bbb",
			At: now.Add(-time.Duration(session) * time.Hour),
		}, private)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(signed)
		if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
			t.Fatalf("ingest: %s", response.Status)
		}
	}

	dashboard := f.service.BuildDashboard(f.orgs["acme"], now)
	if len(dashboard.Machines) != 1 {
		t.Fatalf("machines = %d, want 1", len(dashboard.Machines))
	}
	// One skill, not five sessions. The same counting mistake adoptions already made.
	if got := dashboard.Machines[0].SkillsChanged; got != 1 {
		t.Fatalf("skills changed = %d, want 1 — five sessions reporting one drift is one "+
			"changed skill", got)
	}
	if len(dashboard.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(dashboard.Events))
	}

	attention := strings.Join(dashboard.Attention, "\n")
	if !strings.Contains(attention, "needs attention") {
		t.Errorf("the panel must reflect the failed current check:\n%s", attention)
	}

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	if !strings.Contains(page, "deploy-runbook") {
		t.Fatalf("the skill is never named on the page:\n%s", page)
	}
}

// A drifted skill is not a revocation. Ranking an ordinary edit alongside something an
// organisation withdrew on purpose is how "high" stops meaning anything.
func TestDriftIsNotRankedAsARevocation(t *testing.T) {
	if got := report.KindSkillChanged.Severity(); got != "medium" {
		t.Fatalf("severity = %q, want medium", got)
	}
	if report.KindSkillChanged.Severity() == report.KindRevoked.Severity() {
		t.Error("an edit and a revocation must not share a severity")
	}
}
