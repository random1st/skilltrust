package notary

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

type historicalDirectory struct {
	StaticDirectory
	keys     *attest.TrustedKeys
	machines []Machine
}

func (d historicalDirectory) HistoricalMachineKeys(string) (*attest.TrustedKeys, error) {
	return d.keys, nil
}

func (d historicalDirectory) RegisteredMachines(string) ([]Machine, error) {
	return d.machines, nil
}

type rosterErrorDirectory struct {
	StaticDirectory
	err error
}

func (d rosterErrorDirectory) RegisteredMachines(string) ([]Machine, error) {
	return nil, d.err
}

type checksErrorStorage struct {
	*FileStorage
	err error
}

func (s checksErrorStorage) ListChecks(org string) ([]CheckRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.FileStorage.ListChecks(org)
}

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

func TestDashboardKeepsLegacyEventsVisibleWithUnknownAdmission(t *testing.T) {
	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, notaryKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := Org{
		Name:        "acme",
		IngestToken: NewSecret("ingest-token"),
		AdminToken:  NewSecret("admin-token"),
		Publishers:  attest.NewTrustedKeys(machinePub),
	}
	directory := historicalDirectory{
		StaticDirectory: StaticDirectory{"acme": org},
		keys:            attest.NewTrustedKeys(machinePub),
	}
	service := NewFrom(NewFileStorage(t.TempDir()), directory, notaryKey)
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	envelope, err := report.Sign(report.Event{
		Kind: report.KindRestored, Machine: "old-laptop", Marketplace: "acme",
		Plugin: "deploy-runbook", At: time.Now().UTC(),
	}, machineKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/events/acme", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer ingest-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("legacy ingest answered %s", response.Status)
	}

	request, err = http.NewRequest(http.MethodGet, server.URL+"/ui/acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("admin", "admin-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	for _, expected := range []string{"old-laptop", "Acceptance time unknown", "Disabled"} {
		if !strings.Contains(string(page), expected) {
			t.Fatalf("legacy page does not show %q:\n%s", expected, page)
		}
	}
}

func TestDashboardKeepsCurrentCheckStateWhenNewerEventsAndOtherScopesArrive(t *testing.T) {
	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, notaryKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	org := Org{
		Name:        "acme",
		IngestToken: NewSecret("ingest-token"),
		AdminToken:  NewSecret("admin-token"),
		Publishers:  attest.NewTrustedKeys(machinePub),
		Machines:    attest.NewTrustedKeys(machinePub),
	}
	directory := historicalDirectory{
		StaticDirectory: StaticDirectory{"acme": org},
		machines: []Machine{{
			Name:   "Roman's laptop",
			Signer: attest.KeyID(machinePub),
		}},
	}
	service := NewFrom(NewFileStorage(t.TempDir()), directory, notaryKey)
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	for _, check := range []report.CheckResult{
		{
			Machine:   "signed-machine-name",
			Scope:     report.CheckScopeApprovedSkills,
			Sequence:  1,
			CheckedAt: now.Add(-time.Minute),
			Complete:  true,
			Checked:   2,
		},
		{
			Machine:    "signed-machine-name",
			Scope:      report.CheckScopeManaged,
			Sequence:   2,
			CheckedAt:  now,
			FreshUntil: now.Add(time.Hour),
			Complete:   true,
			Checked:    3,
		},
	} {
		envelope, err := report.SignCheck(check, machineKey)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if response := post(t, server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
			t.Fatalf("check ingest: %s", response.Status)
		}
	}

	eventEnvelope, err := report.Sign(report.Event{
		Kind:        report.KindRestored,
		Machine:     "renamed-by-event",
		Marketplace: "acme",
		Plugin:      "deploy-runbook",
		At:          now.Add(2 * time.Minute),
	}, machineKey)
	if err != nil {
		t.Fatal(err)
	}
	eventBody, err := json.Marshal(eventEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if response := post(t, server.URL+"/v1/events/acme", "ingest-token", eventBody); response.StatusCode != http.StatusOK {
		t.Fatalf("event ingest: %s", response.Status)
	}

	dashboard := service.BuildDashboard(org, now.Add(3*time.Minute))
	if len(dashboard.Machines) != 1 {
		t.Fatalf("machines = %d, want 1", len(dashboard.Machines))
	}
	machine := dashboard.Machines[0]
	if machine.Name != "Roman's laptop" {
		t.Fatalf("fleet row name = %q, want registered display name", machine.Name)
	}
	if !machine.Last.Equal(now) {
		t.Fatalf("checked at = %s, want latest check at %s", machine.Last, now)
	}
	if !machine.FreshUntil.IsZero() {
		t.Fatalf("fresh until = %s, want zero because one required scope omitted it", machine.FreshUntil)
	}
	if machine.Status != "Stale" {
		t.Fatalf("status = %q, want Stale when any required scope is unfresh", machine.Status)
	}
	if machine.ScopeSummary() != report.CheckScopeApprovedSkills+", "+report.CheckScopeManaged {
		t.Fatalf("scope summary = %q", machine.ScopeSummary())
	}
	if dashboard.ActiveMachines != 0 {
		t.Fatalf("active machines = %d, want 0", dashboard.ActiveMachines)
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
// fleets honestly: only machines with a fresh signed current check are active.
func TestActiveMachinesCountsOnlyFreshCurrentChecks(t *testing.T) {
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

	checks := []struct {
		machine string
		key     ed25519.PrivateKey
		at      time.Time
		until   time.Time
	}{
		{"laptop-fresh", freshKey, time.Now().UTC(), time.Now().UTC().Add(time.Hour)},
		{"laptop-stale", staleKey, time.Now().UTC().Add(-2 * time.Hour), time.Now().UTC().Add(-time.Hour)},
	}
	for index, check := range checks {
		signed, err := report.SignCheck(report.CheckResult{
			Machine: check.machine, Scope: "managed", Sequence: int64(index + 1),
			CheckedAt: check.at, FreshUntil: check.until, Complete: true, Checked: 4,
		}, check.key)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(signed)
		if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
			t.Fatalf("check ingest: %s", response.Status)
		}
	}

	response, page := getDashboard(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	if !strings.Contains(page, "1 machine(s) have a current signed check inside its freshness window") {
		t.Fatal("the dashboard must count exactly the fresh machine as active")
	}
	if !strings.Contains(page, "laptop-stale") {
		t.Fatal("the stale machine still belongs in the table; only the active count excludes it")
	}
}

func TestDashboardWarnsWhenLiveRosterCannotBeRead(t *testing.T) {
	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, notaryKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	org := Org{
		Name:        "acme",
		IngestToken: NewSecret("ingest-token"),
		AdminToken:  NewSecret("admin-token"),
		Publishers:  attest.NewTrustedKeys(machinePub),
		Machines:    attest.NewTrustedKeys(machinePub),
	}
	directory := rosterErrorDirectory{
		StaticDirectory: StaticDirectory{"acme": org},
		err:             fmt.Errorf("roster offline"),
	}
	service := NewFrom(NewFileStorage(t.TempDir()), directory, notaryKey)
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	envelope, err := report.SignCheck(report.CheckResult{
		Machine:    "cached-machine",
		Scope:      report.CheckScopeManaged,
		Sequence:   1,
		CheckedAt:  now,
		FreshUntil: now.Add(time.Hour),
		Complete:   true,
		Checked:    3,
	}, machineKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if response := post(t, server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
		t.Fatalf("check ingest: %s", response.Status)
	}

	dashboard := service.BuildDashboard(org, now.Add(10*time.Second))
	if len(dashboard.CurrentStateWarnings) != 1 {
		t.Fatalf("warnings = %v, want 1 roster warning", dashboard.CurrentStateWarnings)
	}
	if got := dashboard.CurrentStateWarnings[0]; !strings.Contains(got, "current list of computers is unavailable") {
		t.Fatalf("warning = %q", got)
	}
	if len(dashboard.Machines) != 1 {
		t.Fatalf("machines = %d, want 1", len(dashboard.Machines))
	}
	if dashboard.Machines[0].Status != "Unknown" {
		t.Fatalf("status = %q, want Unknown", dashboard.Machines[0].Status)
	}
	if dashboard.Machines[0].Checked != 3 {
		t.Fatalf("checked = %d, want 3", dashboard.Machines[0].Checked)
	}
	if dashboard.ActiveMachines != 0 {
		t.Fatalf("active machines = %d, want 0 when roster is unavailable", dashboard.ActiveMachines)
	}
	if len(dashboard.Attention) != 0 {
		t.Fatalf("attention = %v, want none because warnings replace all-clear", dashboard.Attention)
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/ui/acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("admin", "admin-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	page, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	text := string(page)
	for _, expected := range []string{
		"Current state unavailable",
		"current list of computers is unavailable",
		"cached-machine",
		"Unknown",
		"Previously received results are shown below. Current status is unavailable.",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("dashboard page does not show %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{
		"Nothing needs looking at",
		"Every registered machine with a fresh signed check matched what you published.",
		">Checked<",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("dashboard page must not claim %q when roster is unavailable:\n%s", forbidden, text)
		}
	}
}

func TestDashboardWarnsWhenRosterAndChecksAreUnavailable(t *testing.T) {
	publisherPub, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, notaryKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := Org{
		Name:       "acme",
		AdminToken: NewSecret("admin-token"),
		Publishers: attest.NewTrustedKeys(publisherPub),
	}
	directory := rosterErrorDirectory{
		StaticDirectory: StaticDirectory{"acme": org},
		err:             fmt.Errorf("roster offline"),
	}
	storage := checksErrorStorage{
		FileStorage: NewFileStorage(t.TempDir()),
		err:         fmt.Errorf("checks offline"),
	}
	service := NewFrom(storage, directory, notaryKey)
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	dashboard := service.BuildDashboard(org, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	if len(dashboard.CurrentStateWarnings) != 2 {
		t.Fatalf("warnings = %v, want roster and checks warnings", dashboard.CurrentStateWarnings)
	}
	if len(dashboard.Machines) != 0 {
		t.Fatalf("machines = %d, want 0 when both reads fail", len(dashboard.Machines))
	}
	if len(dashboard.Attention) != 0 {
		t.Fatalf("attention = %v, want none", dashboard.Attention)
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/ui/acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("admin", "admin-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	page, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard answered %s", response.Status)
	}
	text := string(page)
	for _, expected := range []string{
		"Current state unavailable",
		"current list of computers is unavailable",
		"The latest checks are unavailable",
		"Computer status is unavailable. Refresh this page to try again.",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("dashboard page does not show %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{
		"Nothing needs looking at",
		"Every registered machine with a fresh signed check matched what you published.",
		"no machine has registered or reported yet",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("dashboard page must not claim %q when current state is unavailable:\n%s", forbidden, text)
		}
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
			{Name: "a", Status: "Needs attention"},
			{Name: "b", Status: "Pending"},
			{Name: "c", Status: "Stale"},
			{Name: "d", Status: "Disabled"},
		},
	})
	joined := strings.Join(busy, " | ")
	for _, expected := range []string{
		"plugins expired",
		"needs attention",
		"has not filed",
		"is stale",
		"is disabled",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("nothing says %q; the page reads: %s", expected, joined)
		}
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
