package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookUsage = `Usage: skillctl hook <subcommand> [flags]

  session-start   reconcile centrally managed skills; for a SessionStart hook
  install         print (or apply) the client configuration for the hook

`

func runHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, hookUsage)
		return exitUsage
	}
	switch args[0] {
	case "session-start":
		return runHookSessionStart(args[1:])
	case "install":
		return runHookInstall(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown hook subcommand %q\n\n%s", args[0], hookUsage)
		return exitUsage
	}
}

type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ", ") }

func (r *repeatedFlag) Set(value string) error {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return err
	}
	*r = append(*r, absolute)
	return nil
}

// claudeSettings is the user-level settings file the hooks are written into.
func claudeSettings(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// clientHooks are the two checks, at the two moments that answer different questions.
//
// SessionStart reports what changed while nobody was looking. It cannot refuse anything —
// the documented behaviour is that its output is shown to the user only — so it is an
// awareness notice and nothing more.
//
// PreToolUse fires immediately before a skill's instructions are loaded, receives the skill
// name in tool_input, and is the one event here that can deny. That is the moment worth
// checking: between "these bytes changed" and "these bytes are about to become instructions
// executed with your credentials" lies the entire difference the tool is for.
//
// Neither is enforcement on a laptop. Anything able to edit a skill can edit these lines,
// and a hook that times out does not block. The claim is detection, at a useful moment.
func clientHooks(executable string) []hookSpec {
	return []hookSpec{{
		Event: "SessionStart", Matcher: "", Command: executable + " hook session-start",
		Why: "restores any centrally managed skill changed here, and says so",
	}}
}

func executablePath() string {
	path, err := os.Executable()
	if err != nil {
		return "skillctl"
	}
	return path
}

func runHookInstall(args []string) int {
	flags := flag.NewFlagSet("hook install", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(),
			"Usage: skillctl hook install [flags]\n\n"+
				"Prints the client configuration for both checks. Nothing is written unless\n"+
				"--apply is given, and --apply keeps a backup.\n\n"+
				"Most people want `skillctl setup`, which does this and the rest.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	client := flags.String("client", "claude", "target client: claude")
	settings := flags.String("settings", "", "settings file to modify (default the client's user settings)")
	apply := flags.Bool("apply", false, "write the change instead of printing it")
	remove := flags.Bool("uninstall", false, "remove skillctl hooks instead of adding them")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if *client != "claude" {
		fmt.Fprintf(os.Stderr, "skillctl: unsupported --client %q\n", *client)
		return exitUsage
	}

	path, err := claudeSettings(*settings)
	if err != nil {
		return fail(err)
	}

	if *remove {
		removed, err := removeClaudeHooks(path, "skillctl")
		if err != nil {
			return fail(err)
		}
		fmt.Printf("removed %d hook%s from %s\n", removed, plural(removed, "", "s"), path)
		return exitClean
	}

	specs := clientHooks(executablePath())

	if !*apply {
		fmt.Printf("Add to %s:\n\n", path)
		for _, spec := range specs {
			encoded, _ := json.MarshalIndent(spec.entry(), "  ", "  ")
			fmt.Printf("  under hooks.%s — %s\n  %s\n\n", spec.Event, spec.Why, encoded)
		}
		fmt.Printf("Apply automatically with: skillctl hook install --apply\n")
		return exitClean
	}

	added, err := applyClaudeHooks(path, specs)
	if err != nil {
		return fail(err)
	}
	if len(added) == 0 {
		fmt.Printf("already configured in %s\n", path)
		return exitClean
	}
	for _, spec := range added {
		fmt.Printf("installed   %s\n", spec.Event)
	}
	fmt.Printf("into        %s\n", path)
	fmt.Printf("backup      %s.skillctl-backup\n", path)
	fmt.Printf("\nUndo with: skillctl hook install --uninstall\n")
	return exitClean
}

// hookSpec is one entry to place in a client's settings.
type hookSpec struct {
	Event   string
	Matcher string
	Command string
	// Why is shown to whoever is being asked to accept this change to their client.
	Why string
}

func (h hookSpec) entry() map[string]any {
	return map[string]any{
		"matcher": h.Matcher,
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": h.Command,
		}},
	}
}

// applyClaudeHooks merges entries into settings.json without disturbing anything else, and
// reports which ones it added.
//
// The whole document is decoded into a generic map and re-encoded, so unknown keys survive
// untouched; rewriting a settings file with a narrower schema is how a tool breaks a client
// it was only supposed to observe. Entries already present are skipped rather than
// duplicated, which is what makes running this twice safe.
func applyClaudeHooks(path string, specs []hookSpec) ([]hookSpec, error) {
	document, err := readSettings(path)
	if err != nil {
		return nil, err
	}

	hooks, _ := document["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	var added []hookSpec
	for _, spec := range specs {
		existing, _ := hooks[spec.Event].([]any)
		if hookAlreadyPresent(existing, spec.Command) {
			continue
		}
		hooks[spec.Event] = append(existing, spec.entry())
		added = append(added, spec)
	}
	if len(added) == 0 {
		return nil, nil
	}
	document["hooks"] = hooks

	if err := writeSettings(path, document); err != nil {
		return nil, err
	}
	return added, nil
}

// removeClaudeHooks strips every entry whose command mentions needle, so what setup wrote
// can be taken back out without hand-editing JSON. A tool that can only be installed is one
// people are right to be wary of installing.
func removeClaudeHooks(path, needle string) (int, error) {
	document, err := readSettings(path)
	if err != nil {
		return 0, err
	}
	hooks, _ := document["hooks"].(map[string]any)
	if hooks == nil {
		return 0, nil
	}

	removed := 0
	for event, value := range hooks {
		groups, ok := value.([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(groups))
		for _, group := range groups {
			if hookAlreadyPresent([]any{group}, needle) {
				removed++
				continue
			}
			kept = append(kept, group)
		}
		if len(kept) == 0 {
			delete(hooks, event)
			continue
		}
		hooks[event] = kept
	}
	if removed == 0 {
		return 0, nil
	}
	document["hooks"] = hooks
	return removed, writeSettings(path, document)
}

// readSettings loads the document and keeps a backup beside it, so any change this tool
// makes to a file it does not own can be undone by copying one file back.
func readSettings(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if err := os.WriteFile(path+".skillctl-backup", raw, 0o600); err != nil {
		return nil, fmt.Errorf("cannot write a backup: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	return document, nil
}

func writeSettings(path string, document map[string]any) error {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	temporary, err := os.CreateTemp(filepath.Dir(path), ".settings.*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func hookAlreadyPresent(groups []any, needle string) bool {
	for _, group := range groups {
		mapping, ok := group.(map[string]any)
		if !ok {
			continue
		}
		entries, _ := mapping["hooks"].([]any)
		for _, item := range entries {
			hook, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if command, ok := hook["command"].(string); ok && strings.Contains(command, needle) {
				return true
			}
		}
	}
	return false
}
