package main

import (
	"bytes"
	"context"
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

// findSkillctl prefers an explicit path, then the binary beside this one, then PATH.
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
		// .exe first on Windows, where the sibling that ships in the same archive is
		// skillctl.exe and a bare "skillctl" matches nothing — so every Windows install
		// silently fell through to PATH, which is the case this lookup exists to beat.
		names := []string{"skillctl"}
		if runtime.GOOS == "windows" {
			names = []string{"skillctl.exe", "skillctl"}
		}
		for _, name := range names {
			sibling := filepath.Join(filepath.Dir(self), name)
			if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
				return sibling, nil
			}
		}
	}
	found, err := exec.LookPath("skillctl")
	if err != nil {
		return "", errors.New("skillctl is not on PATH. Install it from " +
			"https://github.com/random1st/skilltrust/releases, or set SKILLCTL to its path")
	}
	return found, nil
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
	// Combined, because skillctl says which directory it chose and what it skipped on
	// stderr. Dropping that leaves an agent reading a clean report about somewhere it was
	// not asking about.
	var out bytes.Buffer
	command.Stdout = &out
	command.Stderr = &out

	err := command.Run()
	shown := result{
		Command: "skillctl " + strings.Join(args, " "),
		Output:  strings.TrimRight(out.String(), "\n"),
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
