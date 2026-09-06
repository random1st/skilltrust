package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// runner locates and runs skillctl.
//
// The server shells out rather than importing: every command lives in package main, and a
// refactor to expose them is a larger change than this feature. It also keeps one property
// worth more than the tidiness — the bytes that decide whether a skill is trusted are the
// signed, released binary the user installed, not a second implementation compiled into a
// convenience server.
type runner struct {
	binary string
	home   string
}

// findSkillctl prefers an explicit path, then the matching release beside this one,
// then PATH. Axela is the public name; skillctl remains a supported alias.
//
// Beside-this-one comes before PATH because the two ship together: an agent that installed
// a release into a directory it controls should get that release, not whatever older copy a
// shell profile happens to expose.
func findSkillctl() (string, error) {
	if explicit := os.Getenv("SKILLCTL"); explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("SKILLCTL is set to %s, which is not there", explicit)
		}
		return explicit, nil
	}
	if self, err := os.Executable(); err == nil {
		if sibling := bundledCLI(filepath.Dir(self), runtime.GOOS); sibling != "" {
			return sibling, nil
		}
	}
	for _, name := range []string{"axela", "skillctl"} {
		if found, err := exec.LookPath(name); err == nil {
			return found, nil
		}
	}
	return "", errors.New("axela (or its skillctl alias) is not on PATH. Install it from " +
		"https://github.com/random1st/skilltrust/releases, or set SKILLCTL to its path")
}

func bundledCLI(directory, goos string) string {
	names := []string{"axela", "skillctl"}
	if goos == "windows" {
		names = []string{"axela.exe", "skillctl.exe", "axela", "skillctl"}
	}
	for _, name := range names {
		sibling := filepath.Join(directory, name)
		if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
			return sibling
		}
	}
	return ""
}

func displayedCLI(binary string) string {
	switch filepath.Base(binary) {
	case "axela", "axela.exe", "axela.cmd":
		return "axela"
	default:
		return "skillctl"
	}
}

// home is where skillctl keeps the key, the pins and the subscriptions. Resolved the same
// way skillctl resolves it, so a server told about a different home does not describe a
// different machine than the tools change.
func skilltrustHome() string {
	if override := os.Getenv("SKILLTRUST_HOME"); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".skilltrust"
	}
	return filepath.Join(home, ".skilltrust")
}

// result is what a command did, in the shape a tool reports it.
type result struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	// Keep the Go type an object too: the MCP SDK infers the output schema from
	// it, and json.RawMessage is inferred as an array despite marshaling as JSON.
	State map[string]any `json:"state,omitempty"`
}

// run executes skillctl and returns its output whatever the exit code.
//
// A non-zero exit is not an error here. skillctl uses exit codes to say things — sync exits
// 1 when it changed something, lint exits 1 on findings — and a wrapper that turned those
// into failures would report a working reconciliation as a broken tool.
func (r runner) run(ctx context.Context, dir string, args ...string) (result, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	command := exec.CommandContext(ctx, r.binary, args...)
	command.Dir = dir
	if r.home != "" {
		command.Env = append(os.Environ(), "SKILLTRUST_HOME="+r.home)
	}
	// Keep diagnostics visible, while parsing structured state from stdout alone.
	// A refresh can report a fetch problem on stderr and still return useful JSON.
	var out, diagnostics bytes.Buffer
	command.Stdout = &out
	command.Stderr = &diagnostics

	err := command.Run()
	shown := result{
		Command: displayedCLI(r.binary) + " " + strings.Join(args, " "),
		Output:  strings.TrimRight(out.String(), "\n"),
	}
	var state map[string]any
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	decoder.UseNumber()
	if json.Valid(out.Bytes()) && decoder.Decode(&state) == nil {
		shown.State = state
	}
	if diagnostics.Len() > 0 {
		shown.Output += "\n" + strings.TrimRight(diagnostics.String(), "\n")
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		shown.ExitCode = exit.ExitCode()
	case ctx.Err() != nil:
		return shown, fmt.Errorf("%s did not finish within five minutes", shown.Command)
	default:
		return shown, fmt.Errorf("%s could not be run: %w", shown.Command, err)
	}
	return shown, nil
}

// writeTemp puts PEM text on disk for the commands that take a file.
//
// An agent holds a key as a string; skillctl takes a path. Making the caller invent a
// filename is how a public key ends up written into a repository and committed.
func writeTemp(name, contents string) (path string, cleanup func(), err error) {
	if strings.TrimSpace(contents) == "" {
		return "", func() {}, fmt.Errorf("%s is empty", name)
	}
	dir, err := os.MkdirTemp("", "skilltrust-mcp-")
	if err != nil {
		return "", func() {}, err
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(ensureNewline(contents)), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", func() {}, err
	}
	return path, func() { os.RemoveAll(dir) }, nil
}

func ensureNewline(text string) string {
	if strings.HasSuffix(text, "\n") {
		return text
	}
	return text + "\n"
}
