package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func nativeSetupJSON(command, home string, enabled bool) string {
	body, _ := json.Marshal(map[string]any{"enabled": enabled, "transport": map[string]any{"type": "stdio", "command": command, "args": []string{}, "env": map[string]string{"SKILLTRUST_HOME": home}}})
	return string(body)
}

func TestSetupUsesNativeUserConfigurationAndVerifiesItBeforeSuccess(t *testing.T) {
	for _, name := range []string{"claude", "codex"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SKILLTRUST_HOME", "/test/skilltrust")
			old := setupNative
			t.Cleanup(func() { setupNative = old })
			configured := false
			adds := 0
			setupNative = func(binary string, args ...string) (string, int, error) {
				if args[1] == "add" {
					adds++
					expected := []string{"mcp", "add"}
					if name == "claude" {
						expected = append(expected, "--scope", "user")
					}
					expected = append(expected, "skilltrust", "--env", "SKILLTRUST_HOME=/test/skilltrust", "--", "/test/skilltrust-mcp")
					if !reflect.DeepEqual(args, expected) {
						t.Fatalf("native add: %v", args)
					}
					configured = true
					return "saved", 0, nil
				}
				if !configured {
					if name == "claude" {
						return `No MCP server named "skilltrust". Configured servers: none`, 1, nil
					}
					return "No MCP server named 'skilltrust' found.", 1, nil
				}
				if name == "codex" {
					return nativeSetupJSON("/test/skilltrust-mcp", "/test/skilltrust", true), 0, nil
				}
				return "Scope: User config (available in all your projects)\nType: stdio\nCommand: /test/skilltrust-mcp\nArgs:\nEnvironment:\n    SKILLTRUST_HOME=/test/skilltrust\n", 0, nil
			}
			for i := 0; i < 2; i++ {
				out := configureMCPClient(name, name, "/test/skilltrust-mcp")
				if !out.Configured {
					t.Fatalf("%+v", out)
				}
			}
			if adds != 1 {
				t.Fatalf("setup rewrote config %d times", adds)
			}
		})
	}
}

func TestSetupDoesNotOverwriteConflictingOrUnreadableConfiguration(t *testing.T) {
	for _, condition := range []string{"other_command", "disabled", "unreadable", "command_error", "missing_after_save"} {
		t.Run(condition, func(t *testing.T) {
			t.Setenv("SKILLTRUST_HOME", "")
			old := setupNative
			t.Cleanup(func() { setupNative = old })
			adds := 0
			setupNative = func(_ string, args ...string) (string, int, error) {
				if args[1] == "add" {
					adds++
					return "saved", 0, nil
				}
				switch condition {
				case "other_command":
					return nativeSetupJSON("/another-mcp", "", true), 0, nil
				case "disabled":
					return nativeSetupJSON("/test/mcp", "", false), 0, nil
				case "unreadable":
					return "not json", 0, nil
				case "command_error":
					return "sensitive-error-do-not-show", -1, errors.New("native command failed")
				default:
					return "No MCP server named 'skilltrust' found.", 1, nil
				}
			}
			out := configureMCPClient("codex", "codex", "/test/mcp")
			if out.Configured || strings.Contains(out.Detail, "sensitive-error") {
				t.Fatalf("%+v", out)
			}
			if condition != "missing_after_save" && adds != 0 {
				t.Fatal("overwrote existing/unknown configuration")
			}
		})
	}
}

func TestSetupRejectsProjectScopedClaudeConfiguration(t *testing.T) {
	if nativeMCPMatches("claude", "Scope: Local config\nType: stdio\nCommand: /test/mcp\nArgs:\n", "/test/mcp", "") {
		t.Fatal("project configuration became global setup")
	}
}
