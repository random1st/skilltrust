package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Go handler tests would miss a schema that rejects the target before the handler.
// Exercise the MCP transport and inspect what the fake native command receives.
func TestClientSelectionForwardsThroughMCP(t *testing.T) {
	for _, client := range []string{"claude", "codex"} {
		for _, tc := range []struct {
			tool string
			args map[string]any
			want []string
		}{
			{"skilltrust_check", map[string]any{"agent": client, "offline": true},
				[]string{"sync", "-report-only", "--agent", client, "-offline"}},
			{"skilltrust_sync", map[string]any{"agent": client, "offline": true},
				[]string{"sync", "--agent", client, "-offline"}},
			{"skilltrust_install_hook", map[string]any{"client": client, "apply": false},
				[]string{"hook", "install", "--client", client}},
			{"skilltrust_install_hook", map[string]any{"client": client, "apply": true},
				[]string{"hook", "install", "--client", client, "-apply"}},
		} {
			t.Run(tc.tool+"/"+client+"/"+strings.Join(tc.want, "_"), func(t *testing.T) {
				session, _ := connect(t)
				body := callText(t, session, tc.tool, tc.args)
				if got := strings.Fields(body); !reflect.DeepEqual(got, append([]string{"ARGS"}, tc.want...)) {
					t.Fatalf("%s changed the requested client or command mode: %s", tc.tool, body)
				}
			})
		}
	}
}

func TestClientSelectionOmittedKeepsClaudeDefault(t *testing.T) {
	for _, tc := range []struct {
		tool, field string
		args        map[string]any
		want        string
	}{
		{"skilltrust_check", "agent", map[string]any{}, "ARGS sync -report-only"},
		{"skilltrust_sync", "agent", map[string]any{}, "ARGS sync"},
		{"skilltrust_install_hook", "client", map[string]any{"apply": false}, "ARGS hook install"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			session, _ := connect(t)
			// TrimSpace because the fake skillctl on Windows is a .cmd whose echo ends
			// in CRLF; the command itself is still compared exactly.
			if got := strings.TrimSpace(callText(t, session, tc.tool, tc.args)); got != tc.want {
				t.Fatalf("omitting the target changed the existing Claude command: %s", got)
			}
			tc.args[tc.field] = ""
			if got := strings.TrimSpace(callText(t, session, tc.tool, tc.args)); got != tc.want {
				t.Fatalf("an empty optional target must keep the Claude default: %s", got)
			}
		})
	}
}

func TestClientSelectionRejectsUnknownBeforeRunningSkillctl(t *testing.T) {
	for _, tc := range []struct{ tool, field string }{
		{"skilltrust_check", "agent"},
		{"skilltrust_sync", "agent"},
		{"skilltrust_install_hook", "client"},
	} {
		for _, invalid := range []string{"cursor", "Codex", "--apply", " "} {
			t.Run(tc.tool+"/"+invalid, func(t *testing.T) {
				home := t.TempDir()
				name, script := "skillctl", "#!/bin/sh\necho invoked > \"$SKILLTRUST_HOME/invoked\"\necho \"ARGS $@\"\n"
				if runtime.GOOS == "windows" {
					name, script = "skillctl.cmd", "@echo off\r\necho invoked>\"%SKILLTRUST_HOME%\\invoked\"\r\necho ARGS %*\r\n"
				}
				binary := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
				session := connectRunner(t, runner{binary: binary, home: home})
				args := map[string]any{tc.field: invalid}
				if tc.tool == "skilltrust_install_hook" {
					args["apply"] = true
				}
				reply, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: tc.tool, Arguments: args})
				if err != nil {
					t.Fatal(err)
				}
				var body strings.Builder
				for _, content := range reply.Content {
					if text, ok := content.(*mcp.TextContent); ok {
						body.WriteString(text.Text)
					}
				}
				if !reply.IsError || !strings.Contains(body.String(), tc.field+" must be claude or codex") {
					t.Errorf("unsupported target did not return an actionable refusal: %s", body.String())
				}
				if _, err := os.Stat(filepath.Join(home, "invoked")); !os.IsNotExist(err) {
					t.Fatalf("unsupported target reached skillctl before rejection: %v", err)
				}
			})
		}
	}
}
