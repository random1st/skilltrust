package notary

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/internal/attest"
	"github.com/random1st/skilltrust/internal/report"
)

func getDashboard(t *testing.T, f *fixture, password string) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/ui/acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if password != "" {
		request.SetBasicAuth("admin", password)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

// The console shows what the notary knows: the marketplace with its signers, the machine
// that reported, its incident — and events signed by nobody the configuration pins are a
// count, not rows presented as evidence.
func TestDashboardShowsTheOrganisationsState(t *testing.T) {
	f := withEventTokens(newFixture(t))

	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.service.orgs["acme"]
	org.AdminToken = "admin-token"
	org.Machines = attest.NewTrustedKeys(machinePub)
	f.service.orgs["acme"] = org

	if response := f.publish(t, "publish-token", f.signedCatalog(t, 7)); response.StatusCode != http.StatusOK {
		t.Fatalf("publish: %s", response.Status)
	}

	trusted, err := report.Sign(report.Event{
		Kind: report.KindRestored, Machine: "laptop-roman", Marketplace: "acme",
		Plugin: "deploy-runbook", At: time.Now().UTC(),
	}, machineKey)
	if err != nil {
		t.Fatal(err)
	}
	trustedBody, _ := json.Marshal(trusted)
	strangerBody, _ := machineEvent(t) // signed by a key nobody pinned
	for _, body := range [][]byte{trustedBody, strangerBody} {
		if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
			t.Fatalf("ingest: %s", response.Status)
		}
	}

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	for _, expected := range []string{
		"plugins",        // the marketplace table rendered
		"sequence",       // with its sequence column
		"laptop-roman",   // the trusted machine appears
		"deploy-runbook", // with its incident
		"publisher",      // signer roles are named
		"notary",
		"1 stored event(s) are not signed", // the stranger is a count, not a row
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("the dashboard does not show %q", expected)
		}
	}
}

func TestDashboardRequiresTheAdminToken(t *testing.T) {
	f := withEventTokens(newFixture(t))
	org := f.service.orgs["acme"]
	org.AdminToken = "admin-token"
	f.service.orgs["acme"] = org

	for _, password := range []string{"", "wrong", "publish-token", "ingest-token"} {
		response, _ := getDashboard(t, f, password)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("password %q answered %s, not 401", password, response.Status)
		}
	}
	if response, _ := getDashboard(t, f, "admin-token"); response.StatusCode != http.StatusOK {
		t.Fatalf("the admin token must open the console, got %s", response.Status)
	}
}
