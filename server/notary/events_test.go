package notary

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/random1st/skilltrust/internal/attest"
	"github.com/random1st/skilltrust/internal/report"
)

func withEventTokens(f *fixture) *fixture {
	org := f.service.orgs["acme"]
	org.IngestToken = "ingest-token"
	org.AdminToken = "admin-token"
	f.service.orgs["acme"] = org
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
