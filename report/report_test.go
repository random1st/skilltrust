package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func TestAnEventRoundTripsAndCarriesItsSeverity(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{
		Kind: KindRevoked, At: time.Now().UTC(), Machine: "laptop-1",
		Marketplace: "acme", Plugin: "deploy-runbook",
	}, private)
	if err != nil {
		t.Fatal(err)
	}

	event, _, err := Verify(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if event.Severity != "high" {
		t.Fatalf("severity = %q; a receiver routes on this field", event.Severity)
	}
	if event.Summary() == "" {
		t.Fatal("an alert needs a line a human reads first")
	}
}

// An aggregate built from rows nobody signed looks like evidence and is not. Any machine
// could otherwise file a report as any other.
func TestAnEventFromAnUnknownMachineIsRefused(t *testing.T) {
	_, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	stranger, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{Kind: KindRestored, At: time.Now().UTC()}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(envelope, attest.NewTrustedKeys(stranger)); err == nil {
		t.Fatal("an event signed by a machine outside the trusted set must be refused")
	}
}

// A signature over an event must not be replayable as an attestation about a skill, which is
// what binding the payload type into the signed bytes is for.
func TestAnEventSignatureIsNotAnAttestation(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{Kind: KindRestored, At: time.Now().UTC()}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := attest.Verify(envelope, attest.NewTrustedKeys(public)); err == nil {
		t.Fatal("an event envelope must not verify as an attestation")
	}
}

// The one incident worth hearing about is disproportionately likely to be the one that
// happened while the network was unreachable, so events accumulate rather than vanish.
func TestTheSpoolKeepsEventsInOrderAndNeverOverwrites(t *testing.T) {
	_, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	spool := Spool{Directory: filepath.Join(t.TempDir(), "events")}
	at := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)

	var written []string
	for range 3 {
		envelope, err := Sign(Event{Kind: KindRestored, At: at}, private)
		if err != nil {
			t.Fatal(err)
		}
		// The same instant for all three, which is what makes the names collide.
		path, err := spool.Add(envelope, at, "restored")
		if err != nil {
			t.Fatal(err)
		}
		written = append(written, path)
	}

	seen := map[string]struct{}{}
	for _, path := range written {
		if _, repeat := seen[path]; repeat {
			t.Fatalf("%s was written twice; an event overwrote another", path)
		}
		seen[path] = struct{}{}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("spooled event missing: %v", err)
		}
	}

	pending, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 3 {
		t.Fatalf("pending = %d, want 3", len(pending))
	}
	for index := 1; index < len(pending); index++ {
		if pending[index-1] >= pending[index] {
			t.Fatal("a receiver should see events oldest first")
		}
	}
}

// A machine with nowhere to report is a legitimate configuration — but Deliver must say
// that nothing was delivered, not pretend something was. Its caller deletes the spooled
// copy on success, so a nil return here meant a default install wrote every event and
// immediately destroyed it: nothing in the spool, nothing anywhere. The sentinel is what
// keeps this test's own premise true, that "the spool is still readable and an
// administrator can collect it".
func TestNoDestinationsKeepsTheEventSpooled(t *testing.T) {
	err := Deliver(&Config{}, Event{Kind: KindRestored}, nil, time.Second)
	if !errors.Is(err, ErrNoDestinations) {
		t.Fatalf("Deliver with no destinations = %v, want ErrNoDestinations so the "+
			"caller keeps its spooled copy", err)
	}
}

func TestACheckRoundTripsAndOnlyHealthyCoverageReadsHealthy(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignCheck(CheckResult{
		Machine:    "laptop-1",
		Host:       "laptop-1",
		Scope:      CheckScopeManaged,
		Sequence:   7,
		CheckedAt:  time.Now().UTC(),
		FreshUntil: time.Now().UTC().Add(time.Hour),
		Complete:   true,
		Checked:    4,
	}, private)
	if err != nil {
		t.Fatal(err)
	}

	check, signer, err := VerifyCheck(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if signer != attest.KeyID(public) {
		t.Fatalf("signer = %q", signer)
	}
	if check.Version != CheckVersion {
		t.Fatalf("version = %d, want %d", check.Version, CheckVersion)
	}
	if !check.Healthy() {
		t.Fatal("a fresh complete check with coverage and no findings must read healthy")
	}

	empty, err := SignCheck(CheckResult{
		Machine:    "laptop-1",
		Scope:      CheckScopeManaged,
		Sequence:   8,
		CheckedAt:  time.Now().UTC(),
		FreshUntil: time.Now().UTC().Add(time.Hour),
		Complete:   true,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	check, _, err = VerifyCheck(empty, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if check.Healthy() {
		t.Fatal("0 checked must not read healthy")
	}
}

func TestQueuedDeliveryKeepsPerDestinationAcks(t *testing.T) {
	var webhookCalls atomic.Int32
	failWebhook := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalls.Add(1)
		if failWebhook {
			http.Error(w, "still down", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{
		Kind: KindRestored, At: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		Machine: "laptop-1", Host: "laptop-1", Marketplace: "acme", Plugin: "deploy-runbook",
	}, private)
	if err != nil {
		t.Fatal(err)
	}

	spool := Spool{Directory: filepath.Join(t.TempDir(), "events")}
	path, err := spool.Add(envelope, time.Now().UTC(), "restored")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "archive")
	config := &Config{Destinations: []Destination{
		{Kind: "file", Directory: archive},
		{Kind: "webhook", URL: server.URL},
	}}

	if err := DeliverQueuedEvent(path, config, Event{
		Kind: KindRestored, At: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		Machine: "laptop-1", Host: "laptop-1", Marketplace: "acme", Plugin: "deploy-runbook",
	}, body, time.Second); err == nil {
		t.Fatal("first pass must fail while one destination still has not accepted the event")
	}
	stored, err := os.ReadDir(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("file destination wrote %d copies, want 1", len(stored))
	}

	failWebhook = false
	if err := DeliverQueuedEvent(path, config, Event{
		Kind: KindRestored, At: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		Machine: "laptop-1", Host: "laptop-1", Marketplace: "acme", Plugin: "deploy-runbook",
	}, body, time.Second); err != nil {
		t.Fatalf("second pass with every destination healthy: %v", err)
	}
	stored, err = os.ReadDir(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("already-acked file delivery was repeated; archive has %d files", len(stored))
	}
	if calls := webhookCalls.Load(); calls != 2 {
		t.Fatalf("webhook calls = %d, want 2 total attempts", calls)
	}
}

func TestQueuedCurrentChecksNeedAMatchingWebhookReceipt(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	check := CheckResult{
		Machine:    "laptop-1",
		Host:       "laptop-1",
		Scope:      CheckScopeManaged,
		Sequence:   7,
		CheckedAt:  time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		FreshUntil: time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC),
		Complete:   true,
		Checked:    4,
	}
	envelope, err := SignCheck(check, private)
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		receiptBody, err := webhookReceiptForCheckBody(body, attest.KeyID(public))
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(receiptBody)
	}))
	defer server.Close()

	spool := Spool{Directory: filepath.Join(t.TempDir(), "events")}
	path, err := spool.SaveCheck(envelope, check.Scope)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	receiptFile := filepath.Join(t.TempDir(), "receipt.json")
	config := &Config{Destinations: []Destination{{
		Kind:          "webhook",
		URL:           server.URL,
		Payloads:      []string{"checks"},
		HealthyChecks: true,
		ReceiptFile:   receiptFile,
	}}}

	if err := DeliverQueuedCheck(path, config, check, body, time.Second); err == nil {
		t.Fatal("a check webhook must prove which check it accepted")
	}
	if err := DeliverQueuedCheck(path, config, check, body, time.Second); err != nil {
		t.Fatalf("matching receipt should accept the queued check: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("webhook calls = %d, want 2 attempts", calls.Load())
	}
	digest := sha256.Sum256(body)
	receipt, err := os.ReadFile(receiptFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(receipt), hex.EncodeToString(digest[:])) {
		t.Fatalf("receipt file %q does not record the accepted digest", receipt)
	}
}

func TestQueuedCurrentChecksResetLegacyAndStaleAcksWhenTheEnvelopeChanges(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	spool := Spool{Directory: filepath.Join(t.TempDir(), "events")}
	oldEnvelope, err := SignCheck(CheckResult{
		Machine:    "laptop-1",
		Host:       "laptop-1",
		Scope:      CheckScopeManaged,
		Sequence:   7,
		CheckedAt:  now,
		FreshUntil: now.Add(time.Hour),
		Complete:   true,
		Checked:    4,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	path, err := spool.SaveCheck(oldEnvelope, CheckScopeManaged)
	if err != nil {
		t.Fatal(err)
	}
	oldBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest := sha256.Sum256(oldBody)

	newCheck := CheckResult{
		Machine:    "laptop-1",
		Host:       "laptop-1",
		Scope:      CheckScopeManaged,
		Sequence:   8,
		CheckedAt:  now.Add(time.Minute),
		FreshUntil: now.Add(time.Hour),
		Complete:   true,
		Checked:    5,
	}
	newEnvelope, err := SignCheck(newCheck, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.SaveCheck(newEnvelope, newCheck.Scope); err != nil {
		t.Fatal(err)
	}
	newBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		receiptBody, err := webhookReceiptForCheckBody(body, attest.KeyID(public))
		if err != nil {
			t.Fatal(err)
		}
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write(receiptBody)
	}))
	defer server.Close()

	config := &Config{Destinations: []Destination{{
		Kind:          "webhook",
		URL:           server.URL,
		Payloads:      []string{"checks"},
		HealthyChecks: true,
	}}}
	id, err := destinationID(config.Destinations[0])
	if err != nil {
		t.Fatal(err)
	}

	for _, stale := range []struct {
		name  string
		state []byte
	}{
		{
			name: "legacy-sidecar-without-digest",
			state: mustJSON(t, map[string]any{
				"version": 1,
				"acked":   map[string]bool{id: true},
			}),
		},
		{
			name: "new-sidecar-with-the-old-digest",
			state: mustJSON(t, map[string]any{
				"version": 2,
				"digest":  hex.EncodeToString(oldDigest[:]),
				"acked":   map[string]bool{id: true},
			}),
		},
	} {
		t.Run(stale.name, func(t *testing.T) {
			if err := writeSidecarAtomically(ackPath(path), stale.state); err != nil {
				t.Fatal(err)
			}
			calls.Store(0)
			if err := DeliverQueuedCheck(path, config, newCheck, newBody, time.Second); err != nil {
				t.Fatalf("new envelope must be retried after stale ack state: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("stale ack sidecar skipped delivery; webhook calls = %d, want 1", calls.Load())
			}
			if _, err := os.Stat(ackPath(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("all-destination success should remove the ack sidecar, stat error = %v", err)
			}
		})
	}
}

func TestQueuedCurrentChecksKeepExactRetryAcksForTheSameEnvelope(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	check := CheckResult{
		Machine:    "laptop-1",
		Host:       "laptop-1",
		Scope:      CheckScopeManaged,
		Sequence:   7,
		CheckedAt:  time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		FreshUntil: time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC),
		Complete:   true,
		Checked:    4,
	}
	envelope, err := SignCheck(check, private)
	if err != nil {
		t.Fatal(err)
	}
	spool := Spool{Directory: filepath.Join(t.TempDir(), "events")}
	path, err := spool.SaveCheck(envelope, check.Scope)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var firstCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		receiptBody, err := webhookReceiptForCheckBody(body, attest.KeyID(public))
		if err != nil {
			t.Fatal(err)
		}
		firstCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write(receiptBody)
	}))
	defer first.Close()

	var secondCalls atomic.Int32
	failSecond := true
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		if failSecond {
			http.Error(w, "still down", http.StatusBadGateway)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		receiptBody, err := webhookReceiptForCheckBody(body, attest.KeyID(public))
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(receiptBody)
	}))
	defer second.Close()

	config := &Config{Destinations: []Destination{
		{Kind: "webhook", URL: first.URL, Payloads: []string{"checks"}, HealthyChecks: true},
		{Kind: "webhook", URL: second.URL, Payloads: []string{"checks"}, HealthyChecks: true},
	}}

	if err := DeliverQueuedCheck(path, config, check, body, time.Second); err == nil {
		t.Fatal("first pass must fail while one destination still has not accepted the check")
	}
	failSecond = false
	if err := DeliverQueuedCheck(path, config, check, body, time.Second); err != nil {
		t.Fatalf("second pass with every destination healthy: %v", err)
	}
	if firstCalls.Load() != 1 {
		t.Fatalf("first webhook calls = %d, want 1 because same-envelope ack must dedupe retries", firstCalls.Load())
	}
	if secondCalls.Load() != 2 {
		t.Fatalf("second webhook calls = %d, want 2 total attempts", secondCalls.Load())
	}
}

func TestWebhookDestinationsRefuseRedirectsAndCanReadBearerTokensFromOwnerOnlyFiles(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/somewhere-else", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	if err := Deliver(&Config{Destinations: []Destination{{Kind: "webhook", URL: redirect.URL}}},
		Event{Kind: KindRestored}, []byte("{}"), time.Second); err == nil {
		t.Fatal("a redirected webhook must be refused")
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("ingest-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var header string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()

	if err := Deliver(&Config{Destinations: []Destination{{
		Kind: "webhook", URL: ok.URL, BearerTokenFile: tokenFile,
	}}}, Event{Kind: KindRestored}, []byte("{}"), time.Second); err != nil {
		t.Fatal(err)
	}
	if header != "Bearer ingest-token" {
		t.Fatalf("authorization header = %q", header)
	}

	if runtime.GOOS != "windows" {
		loose := filepath.Join(t.TempDir(), "loose-token")
		if err := os.WriteFile(loose, []byte("ingest-token"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := Deliver(&Config{Destinations: []Destination{{
			Kind: "webhook", URL: ok.URL, BearerTokenFile: loose,
		}}}, Event{Kind: KindRestored}, []byte("{}"), time.Second)
		if err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("loose bearer token file error = %v", err)
		}
	}
}

func TestCommandDeliveryStopsWaitingWhenABackgroundChildKeepsThePipeOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell background jobs differ on windows")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not available")
	}

	started := time.Now()
	err = runCommand(Destination{
		Command: []string{shell, "-c", "sleep 1 & exit 0"},
	}, []byte(`{"ok":true}`), 50*time.Millisecond)
	if err == nil {
		t.Fatal("a command that leaves a background child holding the pipe open must not look successful")
	}
	if elapsed := time.Since(started); elapsed > 400*time.Millisecond {
		t.Fatalf("runCommand waited %s after the timeout budget", elapsed)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func webhookReceiptForCheckBody(body []byte, signer string) ([]byte, error) {
	envelope := extractCheckEnvelopeForTest(body)
	if len(envelope) == 0 {
		return nil, errors.New("webhook received neither a bare envelope nor a wrapped one")
	}
	digest := sha256.Sum256(envelope)
	return json.Marshal(map[string]any{
		"receipt": map[string]any{
			"signer":      signer,
			"accepted_at": time.Date(2026, 9, 4, 12, 0, 30, 0, time.UTC).Format(time.RFC3339),
			"digest":      hex.EncodeToString(digest[:]),
		},
	})
}

func extractCheckEnvelopeForTest(body []byte) []byte {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil
	}
	if _, isEnvelope := probe["payloadType"]; isEnvelope {
		return body
	}
	var wrapped struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil || len(wrapped.Envelope) == 0 {
		return nil
	}
	return wrapped.Envelope
}
