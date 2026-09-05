package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

func statusFixture(t *testing.T) (time.Time, ed25519.PrivateKey, report.CheckResult, connectStatusFile) {
	t.Helper()
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	previousAgents := agents
	agents = []agent{known}
	t.Cleanup(func() { agents = previousAgents })
	if _, err := applyClaudeHooks(known.HookConfigPath(), claudeHooks("skillctl")); err != nil {
		t.Fatal(err)
	}
	pub, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), key); err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePublicKey(defaultPublicKey(), pub); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	current := savedConnect{Version: connectRecordVersion, Audience: "https://axela.app", Organisation: "acme", Machine: "Laptop", MachineKeyID: attest.KeyID(pub), IngestURL: "https://axela.app/v1/events", DashboardURL: "https://axela.app/organisations/acme"}
	if err := saveHomeJSON(connectStatePath(), current); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyText(connectCredentialsPath(), "never-show-this-report-token"); err != nil {
		t.Fatal(err)
	}
	check := report.CheckResult{Machine: "Laptop", Scope: CheckScopeManaged, Sequence: 3, CheckedAt: now.Add(-time.Minute), FreshUntil: now.Add(time.Hour), Complete: true, Checked: 2, Catalogs: []report.CatalogCheck{{Name: "acme", Sequence: 4, ValidUntil: now.Add(48 * time.Hour)}}}
	receipt := statusCheck(t, key, check, now)
	return now, key, check, receipt
}

func statusCheck(t *testing.T, key ed25519.PrivateKey, check report.CheckResult, accepted time.Time) connectStatusFile {
	t.Helper()
	envelope, err := report.SignCheck(check, key)
	if err != nil {
		t.Fatal(err)
	}
	path := latestCheckPath(CheckScopeManaged)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Save(path); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := connectStatusFile{Version: connectStatusVersion, AcceptedURL: "https://axela.app/v1/events", Signer: attest.KeyID(key.Public().(ed25519.PublicKey)), Digest: digestHex(body), AcceptedAt: accepted.Format(time.RFC3339)}
	if err := saveHomeJSON(connectStatusPath(), receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestMachineStatusRequiresTheExactAcceptedReport(t *testing.T) {
	now, _, _, receipt := statusFixture(t)
	initial := inspectMachine(now)
	if initial.Status != "connected" || !initial.ReportAccepted {
		t.Fatalf("healthy fixture: %+v", initial)
	}
	body, _ := json.Marshal(initial)
	if strings.Contains(string(body), "never-show-") || strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("status exposed a credential")
	}
	for _, condition := range []string{"digest", "signer", "destination", "past", "future", "malformed_time", "version"} {
		t.Run(condition, func(t *testing.T) {
			changed := receipt
			switch condition {
			case "digest":
				changed.Digest = strings.Repeat("f", 64)
			case "signer":
				changed.Signer = "other-machine"
			case "destination":
				changed.AcceptedURL = "https://another-service.invalid"
			case "past":
				changed.AcceptedAt = now.Add(-time.Hour).Format(time.RFC3339)
			case "future":
				changed.AcceptedAt = now.Add(time.Hour).Format(time.RFC3339)
			case "malformed_time":
				changed.AcceptedAt = "yesterday"
			case "version":
				changed.Version++
			}
			if err := saveHomeJSON(connectStatusPath(), changed); err != nil {
				t.Fatal(err)
			}
			out := inspectMachine(now)
			if out.Status == "connected" || out.ReportAccepted || out.NextAction.Code != "retry_reports" {
				t.Fatalf("accepted wrong %s: %+v", condition, out)
			}
		})
	}
}

func TestMachineStatusRejectsEmptyStaleIncompleteAndWrongMachineChecks(t *testing.T) {
	now, key, check, _ := statusFixture(t)
	for _, condition := range []string{"empty", "stale", "incomplete", "changed", "unapproved", "error", "wrong_machine", "future_check", "wrong_scope"} {
		t.Run(condition, func(t *testing.T) {
			invalid := check
			switch condition {
			case "empty":
				invalid.Checked = 0
			case "stale":
				invalid.FreshUntil = now
			case "incomplete":
				invalid.Complete = false
			case "changed":
				invalid.Changed = 1
			case "unapproved":
				invalid.Unapproved = 1
			case "error":
				invalid.Errors = 1
			case "wrong_machine":
				invalid.Machine = "other-machine"
			case "future_check":
				invalid.CheckedAt = now.Add(10 * time.Minute)
			case "wrong_scope":
				invalid.Scope = CheckScopeApprovedSkills
			}
			statusCheck(t, key, invalid, now)
			out := inspectMachine(now)
			if out.Status == "connected" || out.NextAction.Code != "check_connection" {
				t.Fatalf("accepted %s: %+v", condition, out)
			}
		})
	}
}

func TestMachineStatusGivesExpiredCatalogToThePublisher(t *testing.T) {
	now, key, check, _ := statusFixture(t)
	check.Catalogs[0].ValidUntil = now
	statusCheck(t, key, check, now)
	out := inspectMachine(now)
	if out.Status == "connected" || out.NextAction.Code != "renew_catalog" || out.NextAction.Actor != "publisher" {
		t.Fatalf("expiry: %+v", out)
	}
}

func TestMachineStatusWillNotInventAConnectionFromConfiguration(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	if err := saveHomeJSON(homePath("catalogs.json"), []map[string]string{{"name": "acme"}}); err != nil {
		t.Fatal(err)
	}
	out := inspectMachine(time.Now())
	if out.Status != "not_connected" || out.NextAction.Code != "connect" {
		t.Fatalf("configuration became success: %+v", out)
	}
}

func TestMachineStatusKeepsItsReceiptWhenAnotherScopeIsDelivered(t *testing.T) {
	now, key, check, _ := statusFixture(t)
	endpoint := startConnectReceiptServer(t, key.Public().(ed25519.PublicKey))
	current, err := loadSavedConnect()
	if err != nil {
		t.Fatal(err)
	}
	current.IngestURL = endpoint
	if err := saveHomeJSON(connectStatePath(), current); err != nil {
		t.Fatal(err)
	}
	writeWebhookReportingConfig(t, endpoint, "ingest-token")
	config, err := report.LoadConfig(reportConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{CheckScopeManaged, CheckScopeApprovedSkills} {
		check.Scope = scope
		envelope, err := report.SignCheck(check, key)
		if err != nil {
			t.Fatal(err)
		}
		path := latestCheckPath(scope)
		if err := envelope.Save(path); err != nil {
			t.Fatal(err)
		}
		queued, err := readQueuedReport(path, attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)))
		if err != nil {
			t.Fatal(err)
		}
		if err := deliverQueuedReport(config, queued, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	out := inspectMachine(now)
	if !out.ReportAccepted || out.Status != "connected" {
		t.Fatalf("another scope erased the managed receipt: %+v", out)
	}
}

func TestMachineStatusWarnsBeforeExpiryWithoutFailingAHealthyCheck(t *testing.T) {
	now, key, check, _ := statusFixture(t)
	check.Catalogs[0].ValidUntil = now.Add(24 * time.Hour)
	statusCheck(t, key, check, now)
	out := inspectMachine(now)
	if out.Status != "connected" || !out.ReportAccepted || out.NextAction == nil || out.NextAction.Code != "renew_catalog" || out.NextAction.Actor != "publisher" {
		t.Fatalf("renewal warning: %+v", out)
	}
}
