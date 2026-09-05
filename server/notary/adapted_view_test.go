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

// The dashboard's all-clear said "Every machine that reported found what you published"
// while machines reported running copies nobody published. Adapted is not an incident and
// must not raise an alarm — but the sentence that says nothing is wrong cannot also claim
// something that is false, or the headline stops being worth reading about the machines
// that matter.
//
// The same fixture pins the other half: a machine files its adoption every session, so
// counting events made one adoption read as seven modified copies, and the fifty-row event
// table filled with one reason repeated.
func TestAdoptedCopiesAreCountedOncePerPluginAndQualifyTheAllClear(t *testing.T) {
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
		CheckedAt: now, FreshUntil: now.Add(time.Hour), Complete: true, Checked: 3,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	checkBody, _ := json.Marshal(check)
	if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", checkBody); response.StatusCode != http.StatusOK {
		t.Fatalf("check ingest: %s", response.Status)
	}

	for session := 0; session < 7; session++ {
		signed, err := report.Sign(report.Event{
			Kind: report.KindAdapted, Machine: "laptop-7", Marketplace: "acme",
			Plugin: "deploy-runbook", Detail: "our staging URL, not theirs",
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
	if got := dashboard.Machines[0].Adapted; got != 1 {
		t.Fatalf("adapted = %d, want 1 — seven sessions reporting one adoption is still "+
			"one modified copy", got)
	}
	if len(dashboard.Events) != 1 {
		t.Fatalf("events = %d, want 1 — the table must not fill with one reason repeated",
			len(dashboard.Events))
	}
	if len(dashboard.Attention) != 0 {
		t.Fatalf("an adoption plus a healthy current check must raise nothing: %v", dashboard.Attention)
	}

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	if strings.Contains(page, "Every machine that reported found what you published") {
		t.Fatal("the page still shows the old event-based all-clear")
	}
	if !strings.Contains(page, "modified copy its owner chose to keep") {
		t.Fatalf("the page never says what the fleet is actually running:\n%s", page)
	}
}

// With nothing adopted the plain sentence is true and must stay.
func TestAQuietFleetStillGetsThePlainAllClear(t *testing.T) {
	f := withEventTokens(newFixture(t))
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	f.orgs["acme"] = org

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	if !strings.Contains(page, "Every registered machine with a fresh signed check matched what you published") {
		t.Fatalf("a fleet with nothing adopted must keep the plain all-clear:\n%s", page)
	}
}
