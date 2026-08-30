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

// "No machine keys are registered" and "an event was signed by a key we do not pin" are
// different facts, and used to print one sentence.
//
// The sentence they shared was written for the second: it told the reader that the notary's
// configuration does not pin the key, which is accurate and useless to somebody who has
// never registered one and does not know that is a thing to do. On a hosted service that
// person is the common case — they set the client up themselves, filed reports for a week,
// and watched a counter climb with nothing on the page saying what would make it stop.
func TestAnOrganisationWithNoMachineKeysIsToldSoInThoseWords(t *testing.T) {
	f := withEventTokens(newFixture(t))
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	// Deliberately not registered here: the machine signs, the notary stores, and nothing
	// pins the key that would let it be attributed.
	org.Machines = nil
	f.orgs["acme"] = org

	_, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signed, err := report.Sign(report.Event{
		Kind: report.KindRestored, Machine: "laptop-7", Marketplace: "acme",
		Plugin: "deploy-runbook", At: now,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(signed)
	if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
		t.Fatalf("ingest: %s", response.Status)
	}

	dashboard := f.service.BuildDashboard(f.orgs["acme"], now)
	if !dashboard.NoMachineKeys {
		t.Fatal("an organisation pinning no machine keys must be reported as such")
	}
	if dashboard.Unverified == 0 {
		t.Fatal("the events are still counted; the flag qualifies the count, not replaces it")
	}
	attention := strings.Join(dashboard.Attention, "\n")
	if !strings.Contains(attention, "no machine keys") {
		t.Errorf("the panel does not name the cause:\n%s", attention)
	}
	if !strings.Contains(attention, "register") {
		t.Errorf("the panel does not say what to do:\n%s", attention)
	}

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	if !strings.Contains(page, "registers no machine keys at all") {
		t.Fatalf("the page does not say why the events are missing:\n%s", page)
	}
	// The old wording explained a different situation and must not be what this reader sees.
	if strings.Contains(page, "not signed by any machine key this") {
		t.Error("the page blames an unpinned key when the truth is that none is registered")
	}
}

// The flag qualifies a number that exists. An organisation that has registered nothing and
// filed nothing is new, not broken, and a warning about a state it is not in is how a panel
// of real problems becomes one people scroll past.
func TestANewOrganisationIsNotWarnedAboutMachinesItDoesNotHaveYet(t *testing.T) {
	f := withEventTokens(newFixture(t))
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	org.Machines = nil
	f.orgs["acme"] = org

	dashboard := f.service.BuildDashboard(f.orgs["acme"], time.Now().UTC())
	if dashboard.NoMachineKeys {
		t.Error("an organisation with no events must not be warned about attributing them")
	}
	for _, line := range dashboard.Attention {
		if strings.Contains(line, "machine keys") {
			t.Errorf("nothing has happened yet, but the panel says: %s", line)
		}
	}
}
