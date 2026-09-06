package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func readMachineState(t *testing.T, session *mcp.ClientSession) state {
	t.Helper()
	result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "skilltrust://state"})
	if err != nil {
		t.Fatal(err)
	}
	var current state
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &current); err != nil {
		t.Fatal(err)
	}
	return current
}

func TestLocalSetupStateDoesNotRequireATeam(t *testing.T) {
	for _, subscribed := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "subscribed"}[subscribed], func(t *testing.T) {
			session, home := connect(t)
			if subscribed {
				if err := os.WriteFile(filepath.Join(home, "catalogs.json"), []byte(`[{"name":"example","repository":"https://example.org/skills","key_ids":["publisher"],"threshold":1}]`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			current := readMachineState(t, session)
			if subscribed {
				if !strings.Contains(current.NextStep, "skilltrust_status") || !strings.Contains(current.NextStep, "followed") || strings.Contains(current.NextStep, "skilltrust_connect") {
					t.Fatalf("a followed catalog was routed to team signup: %s", current.NextStep)
				}
			} else if !strings.Contains(current.NextStep, "without an account") || !strings.Contains(current.NextStep, "skilltrust_status") || strings.Contains(current.NextStep, "skilltrust_subscribe") {
				t.Fatalf("empty state has no account-free entry: %s", current.NextStep)
			}
		})
	}
}

func TestLocalSetupStatePreservesVerifiedLocalAndPendingHostedResults(t *testing.T) {
	for _, tc := range []struct {
		name, status, action, want, forbidden string
		approvals                             bool
	}{
		{"local", "local_checked", "", "checked locally", "Axela acknowledged", false},
		{"first-verdict", "not_connected", `,"next_action":{"code":"subscribe","actor":"user","detail":"Follow a publisher with skillctl subscribe."}`, "skilltrust_status", "skilltrust_subscribe", false},
		{"pending", "approval_pending", `,"next_action":{"code":"connect","actor":"user","detail":"Run skillctl connect to resume the saved connection."}`, "skilltrust_connect", "skilltrust_subscribe", false},
		{"expired", "needs_attention", `,"next_action":{"code":"renew_catalog","actor":"publisher","detail":"The publisher must renew the expired catalog with the existing signing key."}`, "publisher", "skilltrust_connect", false},
		{"loose-approvals", "not_connected", `,"next_action":{"code":"subscribe","actor":"user","detail":"Follow a publisher with skillctl subscribe."}`, "skilltrust_verify_skills", "skilltrust_subscribe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.approvals {
				if err := os.MkdirAll(filepath.Join(home, "attestations"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, "attestations", "existing.json"), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			body := `{"status":"` + tc.status + `","report_accepted":false` + tc.action + `}`
			name, script := "skillctl", "#!/bin/sh\nprintf '%s\\n' '"+body+"'\n"
			if runtime.GOOS == "windows" {
				name, script = "skillctl.cmd", "@echo off\r\necho "+body+"\r\n"
			}
			binary := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			session := connectRunner(t, runner{binary: binary, home: home})
			current := readMachineState(t, session)
			if !strings.Contains(current.NextStep, tc.want) || strings.Contains(current.NextStep, tc.forbidden) {
				t.Fatalf("%s next step: %s", tc.name, current.NextStep)
			}
		})
	}
}

func TestLocalSetupPromptUsesTheRequestedRoute(t *testing.T) {
	session, _ := connect(t)
	for _, tc := range []struct {
		name         string
		args         map[string]string
		first, later string
	}{
		{"empty", nil, "skilltrust_subscribe", "skilltrust_connect"},
		{"repository", map[string]string{"repository": "https://example.org/skills"}, "skilltrust_subscribe", "skilltrust_connect"},
		{"team", map[string]string{"service_url": "https://axela.example"}, "skilltrust_connect", "skilltrust_subscribe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "set_up_this_machine", Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			body := result.Messages[0].Content.(*mcp.TextContent).Text
			first, later := strings.Index(body, tc.first), strings.Index(body, tc.later)
			if first < 0 || later < first {
				t.Fatalf("%s route does not lead with %s:\n%s", tc.name, tc.first, body)
			}
			if !strings.Contains(body, "nonempty") || !strings.Contains(body, "expired") {
				t.Fatal("setup has no coverage or freshness completion boundary")
			}
		})
	}
}
