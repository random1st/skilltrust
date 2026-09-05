package notary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

// Exercise the actual spool, webhook, receipt and storage/API representations.
// Individually marshalled fixture envelopes missed whitespace changes between them.
func TestSpooledCurrentCheckHasTheSameBytesInItsReceiptAndReadAPI(t *testing.T) {
	f := withEventTokens(newFixture(t))
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	org := f.orgs["acme"]
	org.Machines = attest.NewTrustedKeys(public)
	f.orgs["acme"] = org
	now := time.Now().UTC()
	check := report.CheckResult{Machine: "work-laptop", Scope: report.CheckScopeManaged,
		Sequence: 1, CheckedAt: now, FreshUntil: now.Add(time.Hour), Complete: true, Checked: 1}
	envelope, err := report.SignCheck(check, private)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	spool := report.Spool{Directory: filepath.Join(root, "events")}
	path, err := spool.SaveCheck(envelope, check.Scope)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("\n")) {
		t.Fatal("test requires actual formatted spool bytes")
	}
	tokenFile := filepath.Join(root, "token")
	if err := os.WriteFile(tokenFile, []byte("ingest-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptFile := filepath.Join(root, "receipt.json")
	config := &report.Config{Destinations: []report.Destination{{
		Kind: "webhook", URL: f.server.URL + "/v1/events/acme", Payloads: []string{"checks"},
		HealthyChecks: true, BearerTokenFile: tokenFile, ReceiptFile: receiptFile,
	}}}
	if err := report.DeliverQueuedCheck(path, config, check, body, time.Second); err != nil {
		t.Fatalf("real notary receipt was refused: %v", err)
	}
	rawReceipt, err := os.ReadFile(receiptFile)
	if err != nil {
		t.Fatal(err)
	}
	var accepted struct{ Digest, Signer string }
	if err := json.Unmarshal(rawReceipt, &accepted); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	wantDigest := hex.EncodeToString(digest[:])
	if accepted.Digest != wantDigest || accepted.Signer != attest.KeyID(public) {
		t.Fatalf("wrong receipt binding: %+v", accepted)
	}
	_, records := listChecks(t, f, "admin-token")
	if len(records) != 1 {
		t.Fatalf("got %d checks", len(records))
	}
	if !bytes.Equal(records[0].Envelope, body) || records[0].Receipt.Digest != wantDigest {
		t.Fatal("check storage or read API changed the bytes bound by the receipt")
	}
	if err := report.DeliverQueuedCheck(path, config, check, body, time.Second); err != nil {
		t.Fatalf("exact retry failed: %v", err)
	}
}
