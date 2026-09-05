package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type setupClient struct {
	Agent      string `json:"agent"`
	Configured bool   `json:"configured"`
	Detail     string `json:"detail"`
}

type setupResult struct {
	Status     string        `json:"status"`
	Clients    []setupClient `json:"clients"`
	NextAction nextAction    `json:"next_action"`
}

var setupLookup = exec.LookPath
var setupNative = func(binary string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	// Native user-scope configuration must not accidentally discover a project's
	// server with the same name and report that as a machine-wide installation.
	cmd.Dir = Home()
	body, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", -1, fmt.Errorf("the client's MCP command timed out")
	}
	if err == nil {
		return string(body), 0, nil
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return string(body), exited.ExitCode(), nil
	}
	return "", -1, err
}

func findMCPBinary() (string, error) {
	name := "skilltrust-mcp"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		sibling := filepath.Join(filepath.Dir(self), name)
		if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
			return preferExecutableLauncher(sibling), nil
		}
	}
	return "", fmt.Errorf("install the full SkillTrust release with both skillctl and skilltrust-mcp, then run skillctl setup again")
}

// Package managers may replace a versioned release directory on upgrade. Persist the
// absolute PATH launcher when it targets this exact binary, never an unrelated install.
func preferExecutableLauncher(expected string) string {
	target, err := os.Stat(expected)
	if err != nil {
		return expected
	}
	launcher, err := exec.LookPath(filepath.Base(expected))
	if err != nil {
		return expected
	}
	launcher, err = filepath.Abs(launcher)
	if err != nil {
		return expected
	}
	candidate, err := os.Stat(launcher)
	if err != nil || !os.SameFile(target, candidate) {
		return expected
	}
	return launcher
}

func configureMCPClient(agentName, binary, mcpBinary string) setupClient {
	out := setupClient{Agent: agentName}
	get := []string{"mcp", "get", "skilltrust"}
	if agentName == "codex" {
		get = append(get, "--json")
	}
	inspect := func() (bool, bool, error) {
		body, code, err := setupNative(binary, get...)
		if err != nil {
			return false, false, err
		}
		if code != 0 {
			message := strings.TrimSpace(body)
			if agentName == "claude" && strings.HasPrefix(message, `No MCP server named "skilltrust".`) ||
				agentName == "codex" && strings.TrimPrefix(message, "Error: ") == "No MCP server named 'skilltrust' found." {
				return false, false, nil
			}
			return false, false, fmt.Errorf("the existing MCP setup could not be read; diagnose it with %s mcp get skilltrust", agentName)
		}
		return true, nativeMCPMatches(agentName, body, mcpBinary, os.Getenv("SKILLTRUST_HOME")), nil
	}
	exists, matches, err := inspect()
	if err != nil {
		out.Detail = err.Error()
		return out
	}
	if exists {
		if matches {
			out.Configured = true
			out.Detail = "Already configured"
		} else {
			out.Detail = "A different skilltrust integration is registered. Review it with " + agentName + " mcp get skilltrust before changing it."
		}
		return out
	}
	args := []string{"mcp", "add"}
	if agentName == "claude" {
		args = append(args, "--scope", "user")
	}
	args = append(args, "skilltrust")
	if home := os.Getenv("SKILLTRUST_HOME"); home != "" {
		args = append(args, "--env", "SKILLTRUST_HOME="+home)
	}
	args = append(args, "--", mcpBinary)
	if _, code, err := setupNative(binary, args...); err != nil || code != 0 {
		out.Detail = "The client could not save its MCP setup. Check " + agentName + " mcp add --help, then retry skillctl setup."
		return out
	}
	exists, matches, err = inspect()
	if err != nil || !exists || !matches {
		out.Detail = "The client accepted setup but its saved configuration could not be verified. Retry skillctl setup."
		return out
	}
	out.Configured = true
	out.Detail = "Configured"
	return out
}

func nativeMCPMatches(agentName, body, expected, expectedHome string) bool {
	var command, configuredHome string
	if agentName == "codex" {
		var config struct {
			Enabled       bool     `json:"enabled"`
			EnabledTools  []string `json:"enabled_tools"`
			DisabledTools []string `json:"disabled_tools"`
			Transport     struct {
				Type    string            `json:"type"`
				Command string            `json:"command"`
				Args    []string          `json:"args"`
				Env     map[string]string `json:"env"`
			} `json:"transport"`
		}
		if json.Unmarshal([]byte(body), &config) != nil || !config.Enabled || config.Transport.Type != "stdio" || len(config.Transport.Args) != 0 || len(config.DisabledTools) != 0 || len(config.EnabledTools) != 0 {
			return false
		}
		if config.Transport.Env["SKILLCTL"] != "" {
			return false
		}
		command, configuredHome = config.Transport.Command, config.Transport.Env["SKILLTRUST_HOME"]
	} else {
		fields := map[string]string{}
		environment := false
		for _, line := range strings.Split(body, "\n") {
			if environment && strings.HasPrefix(line, "    ") {
				if name, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
					fields[name] = value
					continue
				}
			}
			label, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if ok {
				fields[label] = strings.TrimSpace(value)
				environment = label == "Environment"
			}
		}
		if fields["Type"] != "stdio" || fields["Args"] != "" || fields["SKILLCTL"] != "" || !strings.Contains(fields["Scope"], "User") {
			return false
		}
		command, configuredHome = fields["Command"], fields["SKILLTRUST_HOME"]
	}
	if configuredHome != expectedHome {
		return false
	}
	if command == expected {
		return true
	}
	left, leftErr := filepath.EvalSymlinks(command)
	right, rightErr := filepath.EvalSymlinks(expected)
	return leftErr == nil && rightErr == nil && left == right
}

func runSetup(args []string) int {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	client := flags.String("agent", "auto", "claude, codex, or auto for both installed clients")
	asJSON := flags.Bool("json", false, "return setup state as JSON")
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 || (*client != "auto" && *client != "claude" && *client != "codex") {
		return fail(fmt.Errorf("choose --agent claude, codex or auto"))
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return fail(err)
	}
	mcpBinary, err := findMCPBinary()
	if err != nil {
		return fail(err)
	}
	out := setupResult{Status: "configured", Clients: []setupClient{}, NextAction: nextAction{"connect", "user", "Restart your agent and ask: Connect this computer to Axela. Finish its browser approval, then let the agent verify installed skills and report delivery."}}
	for _, name := range []string{"claude", "codex"} {
		if *client != "auto" && *client != name {
			continue
		}
		binary, err := setupLookup(name)
		if err != nil {
			if *client != "auto" {
				out.Clients = append(out.Clients, setupClient{Agent: name, Detail: "Install or open this client's CLI first."})
			}
			continue
		}
		out.Clients = append(out.Clients, configureMCPClient(name, binary, mcpBinary))
	}
	if len(out.Clients) == 0 {
		out.Status = "needs_attention"
		out.NextAction = nextAction{"install_client", "user", "Install Claude Code or Codex CLI, then run skillctl setup."}
	}
	for _, client := range out.Clients {
		if !client.Configured {
			out.Status = "needs_attention"
			out.NextAction = nextAction{"retry_setup", "user", client.Detail}
			break
		}
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		for _, client := range out.Clients {
			fmt.Printf("%s: %s\n", client.Agent, client.Detail)
		}
		fmt.Println(out.NextAction.Detail)
	}
	if out.Status != "configured" {
		return exitFindings
	}
	return exitClean
}
