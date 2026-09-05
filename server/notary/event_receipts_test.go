package notary

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

type receiptAdmission struct {
	org      Org
	disabled bool
}

type receiptHistoryDirectory struct {
	StaticDirectory
	history *attest.TrustedKeys
}

func (d receiptHistoryDirectory) HistoricalMachineKeys(string) (*attest.TrustedKeys, error) {
	return d.history, nil
}

func TestLegacyEventRetainsSignatureAttributionWithoutInventedAdmission(t *testing.T) {
	public, private, _ := attest.GenerateKey()
	_, notaryKey, _ := attest.GenerateKey()
	now := time.Now().UTC()
	org := Org{Name: "acme", Machines: attest.NewTrustedKeys(public)}
	s := New(t.TempDir(), notaryKey, []Org{org})
	envelope, _ := report.Sign(report.Event{Machine: "Work laptop", Kind: report.KindRestored, At: now, Plugin: "legacy-runbook"}, private)
	body, _ := json.Marshal(envelope)
	if _, err := s.AcceptEvent(org, body); err != nil {
		t.Fatal(err)
	}
	org.Machines = attest.NewTrustedKeys()
	s.directory = receiptHistoryDirectory{StaticDirectory: StaticDirectory{"acme": org}, history: attest.NewTrustedKeys(public)}
	dashboard := s.BuildDashboard(org, now)
	if len(dashboard.Events) != 1 || dashboard.Unverified != 0 {
		t.Fatalf("legacy signature attribution disappeared: events=%d unverified=%d", len(dashboard.Events), dashboard.Unverified)
	}
	if _, _, found, err := s.verifyAcceptedEvent(org.Name, body); err != nil || found {
		t.Fatalf("render invented original admission: receipt=%v err=%v", found, err)
	}
	for _, machine := range dashboard.Machines {
		if machine.Status != "Disabled" {
			t.Fatalf("historical key granted current status: %+v", machine)
		}
	}
}

func (a *receiptAdmission) AuthorizeCheck(org, token string, _ time.Time) (Org, *attest.TrustedKeys, error) {
	if a.disabled || org != a.org.Name || token != "machine-token" {
		return Org{}, nil, ErrUnknownOrg
	}
	return a.org, a.org.Machines, nil
}

func TestHostedEventAdmissionKeepsHistoryAndBlocksDisabledUploads(t *testing.T) {
	public, private, _ := attest.GenerateKey()
	_, notaryKey, _ := attest.GenerateKey()
	now := time.Now().UTC()
	org := Org{Name: "acme", Machines: attest.NewTrustedKeys(public), IngestToken: NewSecret("old-shared-token")}
	admission := &receiptAdmission{org: org}
	s := New(t.TempDir(), notaryKey, []Org{org}).WithCheckAdmission(admission)
	envelope, _ := report.Sign(report.Event{Machine: "Work laptop", Kind: report.KindRestored, At: now, Plugin: "runbook"}, private)
	body, _ := json.Marshal(envelope)
	upload := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/events/acme", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := upload("machine-token"); w.Code != http.StatusOK {
		t.Fatalf("bound machine token cannot submit Event v1: %d %s", w.Code, w.Body.String())
	}
	admission.disabled = true
	for _, token := range []string{"machine-token", "old-shared-token"} {
		if w := upload(token); w.Code != http.StatusUnauthorized {
			t.Fatalf("disabled machine bypassed fresh admission with %s: %d", token, w.Code)
		}
	}
	org.Machines = attest.NewTrustedKeys()
	dashboard := s.BuildDashboard(org, now)
	if len(dashboard.Events) != 1 || dashboard.Unverified != 0 {
		t.Fatalf("revocation changed accepted history: events=%d unverified=%d", len(dashboard.Events), dashboard.Unverified)
	}
	for _, machine := range dashboard.Machines {
		if machine.Status != "Disabled" {
			t.Fatalf("historical event made disabled machine look current: %+v", machine)
		}
	}
}

func TestAdmittedEventKeepsItsOriginalEvidenceAfterKeyRemoval(t *testing.T) {
	public, private, _ := attest.GenerateKey()
	_, notaryKey, _ := attest.GenerateKey()
	now := time.Now().UTC()
	org := Org{Name: "acme", Machines: attest.NewTrustedKeys(public)}
	s := New(t.TempDir(), notaryKey, []Org{org})
	envelope, _ := report.Sign(report.Event{Machine: "Work laptop", Kind: report.KindRestored, At: now, Plugin: "runbook"}, private)
	body, _ := json.Marshal(envelope)
	name, err := s.AcceptVerifiedEvent(org, body, org.Machines, now)
	if err != nil {
		t.Fatal(err)
	}
	storage := s.storage.(EventReceiptStorage)
	first, err := storage.GetEventReceipt(org.Name, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptVerifiedEvent(org, body, org.Machines, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	retried, _ := storage.GetEventReceipt(org.Name, name)
	if retried.Receipt.AcceptedAt != first.Receipt.AcceptedAt {
		t.Fatal("retry rewrote the first acceptance time")
	}
	org.Machines = attest.NewTrustedKeys()
	if _, err := s.AcceptVerifiedEvent(org, body, org.Machines, now.Add(time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("disabled signer admitted a new upload: %v", err)
	}
	event, signer, found, err := s.verifyAcceptedEvent(org.Name, body)
	if err != nil || !found || event.Plugin != "runbook" || signer != attest.KeyID(public) {
		t.Fatalf("historical evidence lost: event=%+v signer=%s found=%v err=%v", event, signer, found, err)
	}
	if _, _, found, err := s.verifyAcceptedEvent("other-team", body); err != nil || found {
		t.Fatalf("receipt crossed organisation boundary: found=%v err=%v", found, err)
	}
}

func TestReceiptCannotAdmitAStrangerOrInventLegacyAcceptance(t *testing.T) {
	public, _, _ := attest.GenerateKey()
	_, stranger, _ := attest.GenerateKey()
	_, notaryKey, _ := attest.GenerateKey()
	org := Org{Name: "acme", Machines: attest.NewTrustedKeys(public)}
	s := New(t.TempDir(), notaryKey, []Org{org})
	envelope, _ := report.Sign(report.Event{Machine: "Other laptop", Kind: report.KindRestored, At: time.Now()}, stranger)
	body, _ := json.Marshal(envelope)
	if _, err := s.AcceptVerifiedEvent(org, body, org.Machines, time.Now()); !errors.Is(err, ErrRefused) {
		t.Fatalf("stranger admitted: %v", err)
	}
	// The self-hosted Event v1 mailbox remains wire-compatible and does not
	// manufacture an acceptance claim for legacy uploads it did not verify.
	if _, err := s.AcceptEvent(org, body); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := s.verifyAcceptedEvent(org.Name, body); err != nil || found {
		t.Fatalf("legacy upload acquired invented evidence: found=%v err=%v", found, err)
	}
}
