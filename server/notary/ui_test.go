package notary

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
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
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	org.Machines = attest.NewTrustedKeys(machinePub)
	f.orgs["acme"] = org

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
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	f.orgs["acme"] = org

	for _, password := range []string{"wrong", "publish-token", "ingest-token"} {
		response, _ := getDashboard(t, f, password)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("password %q answered %s, not 401", password, response.Status)
		}
	}
	if response, _ := getDashboard(t, f, "admin-token"); response.StatusCode != http.StatusOK {
		t.Fatalf("the admin token must open the console, got %s", response.Status)
	}
}

// noRedirect reports the first response instead of following it, so a test can assert on
// the redirect itself.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// A browser with no credentials is sent to the login form, not shown a bare 401.
func TestDashboardWithoutCredentialsRedirectsToLogin(t *testing.T) {
	f := withEventTokens(newFixture(t))

	response, err := noRedirect.Get(f.server.URL + "/ui/acme")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("no credentials answered %s, not a redirect", response.Status)
	}
	if location := response.Header.Get("Location"); location != "/login?org=acme" {
		t.Fatalf("redirected to %q, not the login form", location)
	}
}

func TestLoginFormFlow(t *testing.T) {
	f := withEventTokens(newFixture(t))
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	f.orgs["acme"] = org

	// A wrong token re-renders the form as a 401 and sets no cookie.
	response, err := noRedirect.PostForm(f.server.URL+"/login",
		map[string][]string{"org": {"acme"}, "token": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || len(response.Cookies()) != 0 {
		t.Fatalf("a wrong token answered %s with %d cookie(s)", response.Status, len(response.Cookies()))
	}

	// The right token sets the session cookie and lands on the dashboard.
	response, err = noRedirect.PostForm(f.server.URL+"/login",
		map[string][]string{"org": {"acme"}, "token": {"admin-token"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/ui/acme" {
		t.Fatalf("login answered %s → %q", response.Status, response.Header.Get("Location"))
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatalf("login must set exactly one HttpOnly cookie, got %v", cookies)
	}

	// The cookie opens the console without Basic auth.
	request, _ := http.NewRequest(http.MethodGet, f.server.URL+"/ui/acme", nil)
	request.AddCookie(cookies[0])
	response, err = noRedirect.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the session cookie answered %s", response.Status)
	}
	if !strings.Contains(string(body), "sign out") {
		t.Fatal("a session-authenticated page must offer sign out")
	}

	// The same cookie must not open another organisation's console.
	request, _ = http.NewRequest(http.MethodGet, f.server.URL+"/ui/other", nil)
	request.AddCookie(cookies[0])
	response, err = noRedirect.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("another org with a foreign cookie answered %s, not a redirect to login", response.Status)
	}
}

// The landing page is public and names no organisation.
func TestLandingIsPublicAndSilent(t *testing.T) {
	f := withEventTokens(newFixture(t))

	response, err := http.Get(f.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the landing answered %s", response.Status)
	}
	if strings.Contains(string(body), "acme") {
		t.Fatal("the landing page must not name registered organisations")
	}
	if !strings.Contains(string(body), "SkillTrust") {
		t.Fatal("the landing page must present the default brand")
	}

	// A hosted deployment presents itself under its own name.
	f.service.WithBrand("Axela")
	response, err = http.Get(f.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	branded, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(branded), "Axela") || strings.Contains(string(branded), "SkillTrust") {
		t.Fatal("WithBrand must rename the landing page")
	}

	// The root pattern is exact: an unknown path is still a 404, not the landing.
	response, err = http.Get(f.server.URL + "/no-such-page")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown path answered %s, not 404", response.Status)
	}
}

// The active-machine count is the number a per-machine plan meters, so it must count
// fleets honestly: a machine whose last verified report is older than thirty days is
// not a seat, and a machine reporting today is.
func TestActiveMachinesCountsOnlyTheLastThirtyDays(t *testing.T) {
	f := withEventTokens(newFixture(t))

	freshPub, freshKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	stalePub, staleKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	org.Machines = attest.NewTrustedKeys(freshPub, stalePub)
	f.orgs["acme"] = org

	events := []struct {
		machine string
		key     ed25519.PrivateKey
		at      time.Time
	}{
		{"laptop-fresh", freshKey, time.Now().UTC()},
		{"laptop-stale", staleKey, time.Now().UTC().AddDate(0, 0, -45)},
	}
	for _, e := range events {
		signed, err := report.Sign(report.Event{
			Kind: report.KindRestored, Machine: e.machine, Marketplace: "acme",
			Plugin: "deploy-runbook", At: e.at,
		}, e.key)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(signed)
		if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
			t.Fatalf("ingest: %s", response.Status)
		}
	}

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	if !strings.Contains(page, "1 reported in the last 30 days") {
		t.Fatal("the dashboard must count exactly the fresh machine as active")
	}
	if !strings.Contains(page, "laptop-stale") {
		t.Fatal("the stale machine still belongs in the table; only the active count excludes it")
	}
}

// The page answers the question people open it to ask, instead of leaving them to work it
// out from three tables and six columns of zeros. Both halves matter: a quiet fleet has to
// say so, or silence reads as "nothing loaded".
func TestTheDashboardSaysWhetherAnythingNeedsLookingAt(t *testing.T) {
	now := time.Now().UTC()

	quiet := whatNeedsLookingAt(Dashboard{Now: now, Machines: []MachineView{
		{Name: "laptop", Last: now.Add(-time.Hour)},
	}})
	if len(quiet) != 0 {
		t.Errorf("a fleet with nothing wrong must raise nothing, got %v", quiet)
	}

	busy := whatNeedsLookingAt(Dashboard{
		Now: now,
		Marketplaces: []MarketplaceView{
			{Name: "plugins", Expired: true, ValidUntil: now.AddDate(0, 0, -1)},
		},
		Machines: []MachineView{
			{Name: "a", Last: now, Revoked: 1},
			{Name: "b", Last: now, Restored: 2},
			{Name: "c", Last: now, Unverifiable: 1},
			{Name: "d", Last: now.AddDate(0, 0, -40)},
		},
	})
	joined := strings.Join(busy, " | ")
	for _, expected := range []string{
		"plugins expired",   // the catalog nobody accepts any more
		"revoked",           // the one that means something withdrawn was found
		"put the published", // a skill was changed and restored
		"went unchecked",    // and the state that must never read as fine
		"has not reported",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("nothing says %q; the page reads: %s", expected, joined)
		}
	}

	// Revocation is the only line meaning a machine ran into something you withdrew. It
	// must not be third in a list of counters.
	if !strings.HasPrefix(busy[1], "1 machine found a skill you revoked") {
		t.Errorf("revocation must come before the softer counts, got %q", busy[1])
	}
}

// Counting reads as English or it does not get read. "1 machines" is the kind of thing that
// makes a reader stop trusting the rest of the number.
func TestCountsReadAsEnglish(t *testing.T) {
	if got := plural(1, "machine"); got != "1 machine" {
		t.Errorf("plural(1) = %q", got)
	}
	if got := plural(3, "machine"); got != "3 machines" {
		t.Errorf("plural(3) = %q", got)
	}
}
