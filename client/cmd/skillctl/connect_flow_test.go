package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
	"github.com/random1st/skilltrust/server/notary"
)

type runFirstCheckFixture struct {
	connectInstallFixture
	agent         agent
	machinePublic ed25519.PublicKey
}

func TestRunFirstCheckReturnsVerifiedWhenManagedPluginAndReceiptAreHealthy(t *testing.T) {
	fixture := prepareRunFirstCheckFixture(t)
	installManagedPluginFixture(t, fixture)

	receiptURL := startConnectReceiptServer(t, fixture.machinePublic)
	writeWebhookReportingConfig(t, receiptURL, "ingest-token")

	checked, verified, notes := runFirstCheck()
	if !checked {
		t.Fatalf("checked = false, want true; notes=%v", notes)
	}
	if !verified {
		t.Fatalf("verified = false, want true; notes=%v", notes)
	}
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none", notes)
	}

	status := readConnectStatus(t)
	if status.AcceptedURL != receiptURL {
		t.Fatalf("accepted url = %q, want %q", status.AcceptedURL, receiptURL)
	}
	if status.Signer != attest.KeyID(fixture.machinePublic) {
		t.Fatalf("receipt signer = %q, want %q", status.Signer, attest.KeyID(fixture.machinePublic))
	}
	if status.Digest == "" {
		t.Fatal("receipt digest is empty")
	}
}

func TestRunFirstCheckRejectsStaleTamperedReceiptWhenDeliveryCannotRefresh(t *testing.T) {
	fixture := prepareRunFirstCheckFixture(t)
	installManagedPluginFixture(t, fixture)

	receiptURL := startConnectReceiptServer(t, fixture.machinePublic)
	writeWebhookReportingConfig(t, receiptURL, "ingest-token")

	checked, verified, notes := runFirstCheck()
	if !checked || !verified {
		t.Fatalf("setup run failed: checked=%v verified=%v notes=%v", checked, verified, notes)
	}

	tampered := connectStatusFile{
		Version:     connectStatusVersion,
		AcceptedURL: receiptURL,
		AcceptedAt:  connectNow().Add(-10 * time.Minute).Format(time.RFC3339),
		Signer:      attest.KeyID(fixture.machinePublic),
		Digest:      strings.Repeat("ab", 32),
	}
	if err := saveHomeJSON(connectStatusPath(), tampered); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyText(connectCredentialsPath(), "wrong-token"); err != nil {
		t.Fatal(err)
	}

	checked, verified, notes = runFirstCheck()
	if !checked {
		t.Fatalf("checked = false, want true; notes=%v", notes)
	}
	if verified {
		t.Fatalf("verified = true, want false; notes=%v", notes)
	}
	if !containsString(notes, receiptStatusNote()) {
		t.Fatalf("notes = %v, want %q", notes, receiptStatusNote())
	}

	status := readConnectStatus(t)
	if status.AcceptedAt != tampered.AcceptedAt || status.Digest != tampered.Digest {
		t.Fatalf("tampered receipt was replaced unexpectedly: %+v", status)
	}
}

func TestRunFirstCheckLeavesEmptyManagedCacheUnverifiedWhenNativeInstallFails(t *testing.T) {
	fixture := prepareRunFirstCheckFixture(t)
	writeFileReportingConfig(t)

	stubNativeInstall(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("native install ran without a deadline")
			}
			return []byte("install refused"), errors.New("exit 1")
		})

	checked, verified, notes := runFirstCheck()
	if checked {
		t.Fatalf("checked = true, want false; notes=%v", notes)
	}
	if verified {
		t.Fatalf("verified = true, want false; notes=%v", notes)
	}
	if !notesContainSnippet(notes, "install refused") {
		t.Fatalf("notes = %v, want install failure", notes)
	}
	if !containsString(notes, "no signed plugin from the followed catalogs is installed in the managed clients yet") {
		t.Fatalf("notes = %v, want empty-cache guidance", notes)
	}
	installed := marketplace.InstalledPath(fixture.agent.Home(), fixture.subscription.Name, "runbook", "1.0.0")
	if _, err := os.Stat(installed); !os.IsNotExist(err) {
		t.Fatalf("install path exists after failed native install: %s", installed)
	}
}

func prepareRunFirstCheckFixture(t *testing.T) runFirstCheckFixture {
	t.Helper()
	fixture := prepareConnectInstallFixture(t)
	attachManagedSourceOrigin(t, fixture.sourceRoot)

	claudeHome := os.Getenv("CLAUDE_CONFIG_DIR")
	if err := os.MkdirAll(claudeHome, 0o755); err != nil {
		t.Fatal(err)
	}

	machinePublic, machinePrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), machinePrivate); err != nil {
		t.Fatal(err)
	}

	agent, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	if !agent.Managed {
		t.Fatalf("agent %q is not managed", agent.Name)
	}
	return runFirstCheckFixture{
		connectInstallFixture: fixture,
		agent:                 agent,
		machinePublic:         machinePublic,
	}
}

func attachManagedSourceOrigin(t *testing.T, sourceRoot string) {
	t.Helper()
	if err := testMarketplaceGit(sourceRoot, "add", "."); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(sourceRoot, "commit", "--quiet", "-m", "publish catalog"); err != nil {
		t.Fatal(err)
	}
	origin := filepath.Join(t.TempDir(), "acme-origin.git")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(origin, "init", "--bare", "--quiet"); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(sourceRoot, "remote", "add", "origin", origin); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(sourceRoot, "push", "--quiet", "-u", "origin", "main"); err != nil {
		t.Fatal(err)
	}
}

func installManagedPluginFixture(t *testing.T, fixture runFirstCheckFixture) {
	t.Helper()
	installed := marketplace.InstalledPath(fixture.agent.Home(), fixture.subscription.Name, "runbook", "1.0.0")
	copyTree(t, installed, fixture.pluginRoot)
}

func startConnectReceiptServer(t *testing.T, machinePublic ed25519.PublicKey) string {
	t.Helper()
	publisherPublic, serviceKey, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	service := notary.NewFrom(
		notary.NewFileStorage(t.TempDir()),
		notary.StaticDirectory{
			"acme": {
				Name:        "acme",
				IngestToken: notary.NewSecret("ingest-token"),
				Publishers:  attest.NewTrustedKeys(publisherPublic),
				Machines:    attest.NewTrustedKeys(machinePublic),
			},
		},
		serviceKey,
	)
	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)
	return server.URL + "/v1/events/acme"
}

func writeWebhookReportingConfig(t *testing.T, url, token string) {
	t.Helper()
	if err := writeOwnerOnlyText(connectCredentialsPath(), token); err != nil {
		t.Fatal(err)
	}
	if err := saveHomeJSON(reportConfigPath(), report.Config{
		TimeoutSeconds: reportTimeoutSeconds,
		Destinations: []report.Destination{{
			Kind:            "webhook",
			URL:             url,
			Payloads:        []string{"checks"},
			HealthyChecks:   true,
			BearerTokenFile: connectCredentialsPath(),
			ReceiptFile:     connectStatusPath(),
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func writeFileReportingConfig(t *testing.T) {
	t.Helper()
	if err := saveHomeJSON(reportConfigPath(), report.Config{
		TimeoutSeconds: reportTimeoutSeconds,
		Destinations: []report.Destination{{
			Kind:          "file",
			Directory:     filepath.Join(t.TempDir(), "report-sink"),
			Payloads:      []string{"checks"},
			HealthyChecks: true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func readConnectStatus(t *testing.T) connectStatusFile {
	t.Helper()
	raw, err := os.ReadFile(connectStatusPath())
	if err != nil {
		t.Fatal(err)
	}
	var status connectStatusFile
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func notesContainSnippet(notes []string, snippet string) bool {
	for _, note := range notes {
		if strings.Contains(note, snippet) {
			return true
		}
	}
	return false
}
