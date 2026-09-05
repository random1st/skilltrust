package notary

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

func withEventTokens(f *fixture) *fixture {
	org := f.orgs["acme"]
	org.IngestToken = NewSecret("ingest-token")
	org.AdminToken = NewSecret("admin-token")
	f.orgs["acme"] = org
	return f
}

func machineEvent(t *testing.T) ([]byte, attest.Envelope) {
	t.Helper()
	_, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := report.Sign(report.Event{
		Kind: report.KindRestored, Machine: "laptop-1", Marketplace: "acme",
		Plugin: "deploy-runbook", At: time.Now().UTC(),
	}, machineKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body, *envelope
}

func machineCheck(t *testing.T, key ed25519.PrivateKey, checked int, sequence int64) []byte {
	t.Helper()
	envelope, err := report.SignCheck(report.CheckResult{
		Machine:    "laptop-1",
		Host:       "laptop-1",
		Scope:      report.CheckScopeManaged,
		Sequence:   sequence,
		CheckedAt:  time.Now().UTC(),
		FreshUntil: time.Now().UTC().Add(time.Hour),
		Complete:   true,
		Checked:    checked,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func post(t *testing.T, url, token string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func listEvents(t *testing.T, f *fixture, token string) (*http.Response, []json.RawMessage) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/v1/events/acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		return response, nil
	}
	var payload struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return response, payload.Events
}

func listChecks(t *testing.T, f *fixture, token string) (*http.Response, []CheckRecord) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/v1/checks/acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		return response, nil
	}
	var payload struct {
		Checks []CheckRecord `json:"checks"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return response, payload.Checks
}

// A bare envelope and the webhook's notification wrapper both land as the same stored
// event, and redelivery of either is one file, not two rows in somebody's count.
func TestEventsAreStoredOnceHoweverTheyArrive(t *testing.T) {
	f := withEventTokens(newFixture(t))
	bare, _ := machineEvent(t)
	wrapped, err := json.Marshal(map[string]any{
		"text": "restored deploy-runbook", "severity": "warning",
		"envelope": json.RawMessage(bare),
	})
	if err != nil {
		t.Fatal(err)
	}

	url := f.server.URL + "/v1/events/acme"
	for _, body := range [][]byte{bare, wrapped, bare} {
		if response := post(t, url, "ingest-token", body); response.StatusCode != http.StatusOK {
			t.Fatalf("ingest answered %s", response.Status)
		}
	}

	_, events := listEvents(t, f, "admin-token")
	if len(events) != 1 {
		t.Fatalf("%d events stored; three deliveries of one event must be one file", len(events))
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(events[0], &envelope); err != nil {
		t.Fatalf("the stored event is not an envelope: %v", err)
	}
	if envelope.PayloadType != report.PayloadType {
		t.Fatalf("stored payload type %q", envelope.PayloadType)
	}
}

func TestEventRolesAreSeparate(t *testing.T) {
	f := withEventTokens(newFixture(t))
	body, _ := machineEvent(t)
	url := f.server.URL + "/v1/events/acme"

	// The publish token must not file events, and the ingest token must not read them:
	// a leaked CI credential should not let anyone fake incidents, and a machine's
	// credential should not let it browse the fleet.
	for _, token := range []string{"", "publish-token", "admin-token", "wrong"} {
		if response := post(t, url, token, body); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("ingest with token %q answered %s, not 401", token, response.Status)
		}
	}
	for _, token := range []string{"", "publish-token", "ingest-token", "wrong"} {
		if response, _ := listEvents(t, f, token); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("reading events with token %q answered %s, not 401", token, response.Status)
		}
	}
}

func TestAnUnsignedOrAlienEventIsRefused(t *testing.T) {
	f := withEventTokens(newFixture(t))
	url := f.server.URL + "/v1/events/acme"

	unsigned, err := json.Marshal(attest.Envelope{
		PayloadType: report.PayloadType, Payload: "e30=",
	})
	if err != nil {
		t.Fatal(err)
	}
	catalogEnvelope := f.signedCatalog(t, 1)

	for name, body := range map[string][]byte{
		"garbage":            []byte("not json"),
		"unsigned":           unsigned,
		"a catalog envelope": catalogEnvelope,
	} {
		if response := post(t, url, "ingest-token", body); response.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s answered %s, not 422", name, response.Status)
		}
	}
}

// An organisation that configured no event tokens has the endpoints closed, not open.
func TestMissingEventTokensDisableTheEndpoints(t *testing.T) {
	f := newFixture(t)
	body, _ := machineEvent(t)

	if response := post(t, f.server.URL+"/v1/events/acme", "", body); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ingest with no configured token answered %s, not 401", response.Status)
	}
	if response, _ := listEvents(t, f, ""); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reading with no configured token answered %s, not 401", response.Status)
	}
}

func TestChecksKeepOnlyTheLatestResultPerSignerAndScope(t *testing.T) {
	f := withEventTokens(newFixture(t))
	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.Machines = attest.NewTrustedKeys(machinePub)
	f.orgs["acme"] = org

	for _, submission := range []struct {
		body   []byte
		status int
	}{
		{body: machineCheck(t, machineKey, 2, 3), status: http.StatusOK},
		{body: machineCheck(t, machineKey, 5, 3), status: http.StatusUnprocessableEntity},
		{body: machineCheck(t, machineKey, 1, 2), status: http.StatusUnprocessableEntity},
	} {
		response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", submission.body)
		if response.StatusCode != submission.status {
			t.Fatalf("ingest answered %s, want %d", response.Status, submission.status)
		}
	}

	response, checks := listChecks(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("checks answered %s", response.Status)
	}
	if len(checks) != 1 {
		t.Fatalf("%d checks stored; latest state must stay bounded to one row per signer and scope", len(checks))
	}
	if checks[0].Result.Checked != 2 || checks[0].Result.Sequence != 3 {
		t.Fatalf("stored %+v, want the first accepted sequence and not a same-sequence overwrite or rollback", checks[0].Result)
	}
	if checks[0].Receipt.Signer != attest.KeyID(machinePub) {
		t.Fatalf("receipt signer = %q", checks[0].Receipt.Signer)
	}
	if checks[0].Receipt.AcceptedAt.IsZero() {
		t.Fatal("the server receipt must stamp when it accepted the check")
	}
}

type fixedCheckAdmission struct {
	org     Org
	token   string
	trusted *attest.TrustedKeys
}

func (a fixedCheckAdmission) AuthorizeCheck(orgName, token string, _ time.Time) (Org, *attest.TrustedKeys, error) {
	if orgName != a.org.Name || token != a.token {
		return Org{}, nil, ErrUnknownOrg
	}
	return a.org, a.trusted, nil
}

func TestChecksCanUseAMachineBoundTokenWithoutTheSharedIngestToken(t *testing.T) {
	f := newFixture(t)
	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	org.IngestToken = NewSecret("shared-token")
	org.Machines = attest.NewTrustedKeys(machinePub)
	f.orgs["acme"] = org
	f.service.WithCheckAdmission(fixedCheckAdmission{
		org: org, token: "machine-token", trusted: attest.NewTrustedKeys(machinePub),
	})

	if response := post(t, f.server.URL+"/v1/events/acme", "wrong", machineCheck(t, machineKey, 4, 7)); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong machine token answered %s, not 401", response.Status)
	}
	if response := post(t, f.server.URL+"/v1/events/acme", "shared-token", machineCheck(t, machineKey, 4, 7)); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("shared ingest token answered %s, not 401 once strong admission is enabled", response.Status)
	}
	if response := post(t, f.server.URL+"/v1/events/acme", "machine-token", machineCheck(t, machineKey, 4, 7)); response.StatusCode != http.StatusOK {
		t.Fatalf("machine-bound token answered %s", response.Status)
	}

	response, checks := listChecks(t, f, "admin-token")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("checks answered %s", response.Status)
	}
	if len(checks) != 1 || checks[0].Receipt.Signer != attest.KeyID(machinePub) {
		t.Fatalf("stored checks = %+v", checks)
	}
}

func TestChecksRolesStaySeparateToo(t *testing.T) {
	f := withEventTokens(newFixture(t))
	machinePub, machineKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.Machines = attest.NewTrustedKeys(machinePub)
	f.orgs["acme"] = org
	body := machineCheck(t, machineKey, 4, 7)

	if response := post(t, f.server.URL+"/v1/events/acme", "ingest-token", body); response.StatusCode != http.StatusOK {
		t.Fatalf("ingest answered %s", response.Status)
	}
	for _, token := range []string{"", "publish-token", "ingest-token", "wrong"} {
		if response, _ := listChecks(t, f, token); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("reading checks with token %q answered %s, not 401", token, response.Status)
		}
	}
}

func TestCheckAdmissionDoesNotReplaceSignatureVerification(t *testing.T) {
	f := newFixture(t)
	machinePub, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, strangerKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.AdminToken = NewSecret("admin-token")
	f.orgs["acme"] = org
	f.service.WithCheckAdmission(fixedCheckAdmission{
		org: org, token: "machine-token", trusted: attest.NewTrustedKeys(machinePub),
	})

	response := post(t, f.server.URL+"/v1/events/acme", "machine-token", machineCheck(t, strangerKey, 4, 7))
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a check signed by the wrong key answered %s, not 422", response.Status)
	}
}
