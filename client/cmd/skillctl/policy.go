package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
)

// managedSettingsPath is where an organisation places a policy on each operating system.
// These are system directories a developer cannot write to, which is the entire point.
func managedSettingsPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	case "windows":
		return `C:\Program Files\ClaudeCode\managed-settings.json`
	default:
		return "/etc/claude-code/managed-settings.json"
	}
}

// runPolicy prints the managed settings that make this tool enforcement rather than
// detection.
//
// Everything else in this project is careful to say that on a laptop anything able to edit a
// skill can edit the check. Managed settings are the exception, and the only one: they live
// in a system directory the developer does not own, nothing they set overrides them, and
// Claude Code documents that `--plugin-dir` cannot override a plugin they force-enable. That
// is a boundary, not a convention.
//
// The command prints rather than installs. Writing into a system policy directory from a
// developer tool would be both wrong and useless — wrong because it needs privileges the tool
// should not ask for, useless because a policy that one machine can grant itself is not a
// policy. It belongs in the same MDM or configuration management that already places files on
// the fleet.
func runPolicy(args []string) int {
	flags := flag.NewFlagSet("policy", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl policy [flags]\n\n"+
			"Prints the Claude Code managed settings that confine a machine to plugins your\n"+
			"organisation signed. Deploy it with whatever already places files on your fleet.\n\n"+
			"Exit codes: %d printed, %d error.\n\nFlags:\n", exitClean, exitUsage)
		flags.PrintDefaults()
	}

	name := flags.String("marketplace", "", "marketplace name, as it appears in marketplace.json")
	repo := flags.String("repo", "", "github repository hosting it, as owner/name")
	plugin := flags.String("plugin", "skilltrust", "SkillTrust plugin name to force on")
	lockdown := flags.Bool("lockdown", false,
		"also forbid every marketplace but yours, including Anthropic's")
	out := flags.String("out", "", "write to a file instead of standard output")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if *name == "" || *repo == "" {
		flags.Usage()
		fmt.Fprintln(flags.Output(), "\n--marketplace and --repo are both required.")
		return exitUsage
	}

	settings := map[string]any{
		// Register the marketplace so a fresh machine has it without anyone typing a command.
		"extraKnownMarketplaces": map[string]any{
			*name: map[string]any{
				"source": map[string]any{"source": "github", "repo": *repo},
			},
		},
		// Force SkillTrust on. A check a developer can switch off is a suggestion.
		"enabledPlugins": map[string]any{
			*plugin + "@" + *name: true,
		},
		// Skills, agents, hooks and MCP servers may come only from plugins — which, with the
		// marketplace allowlist below, means only from a marketplace you signed. Without
		// this, a user-level skill in ~/.claude/skills runs with no signature at all and the
		// whole scheme is decoration.
		"strictPluginOnlyCustomization": map[string]any{
			"skills": true, "agents": true, "hooks": true, "mcp": true,
		},
		// Only hooks a managed source declares may run. This is what stops the check being
		// removed by the machine it checks.
		"allowManagedHooksOnly": true,
		// Reject the flags that sideload a plugin, agent or MCP server for one run.
		"disableSideloadFlags": true,
		// A command source fetches its plugin by running a command, which the marketplace
		// allowlist does not constrain.
		"disableCommandPluginSources": true,
	}

	if *lockdown {
		settings["strictKnownMarketplaces"] = []any{
			map[string]any{"source": "github", "repo": *repo},
		}
	}

	body, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fail(err)
	}
	body = append(body, '\n')

	if *out != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return fail(err)
		}
		fmt.Printf("written to %s\n\n", *out)
	} else {
		fmt.Printf("%s", body)
		fmt.Println()
	}

	fmt.Printf("Place this as managed-settings.json in the system directory for each platform:\n")
	fmt.Printf("  macOS    /Library/Application Support/ClaudeCode/managed-settings.json\n")
	fmt.Printf("  Linux    /etc/claude-code/managed-settings.json\n")
	fmt.Printf("  Windows  C:\\Program Files\\ClaudeCode\\managed-settings.json\n\n")
	fmt.Printf("Confirm it applied by running /status in Claude Code: the \"Setting sources\"\n")
	fmt.Printf("line names the managed source when a policy is in force.\n\n")

	fmt.Printf("What this does and does not do:\n")
	fmt.Printf("  · a developer cannot edit these paths, so the check cannot be switched off\n")
	fmt.Printf("    on the machine it checks — this is the one place this tool is enforcement\n")
	fmt.Printf("    rather than detection\n")
	fmt.Printf("  · it does not verify the plugins themselves; that is what a signed\n")
	fmt.Printf("    marketplace and `skillctl sync` are for. Policy decides what may run,\n")
	fmt.Printf("    signatures decide whether what runs is what you published\n")
	if !*lockdown {
		fmt.Printf("  · other marketplaces remain addable. Pass --lockdown to allow only yours,\n")
		fmt.Printf("    which also blocks Anthropic's official one\n")
	} else {
		fmt.Printf("  · no other marketplace may be added, including Anthropic's official one\n")
	}
	return exitClean
}
