package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// An agent is a client that installs skills on this machine and can be asked to check them
// before it runs.
//
// There is more than one now, and the second one cost almost nothing to support, because the
// thing this tool actually needs from a client is small: a directory laid out as
// <home>/plugins/cache/<marketplace>/<plugin>/<version>, and a moment before the session
// starts where a command can run. Codex CLI has both, in the same shapes — it installs the
// same plugins from the same marketplaces, `.claude-plugin/plugin.json` and all.
//
// What differs between clients is a home directory, the file hooks are configured in, and
// which moments that client offers. Those three are what this type holds. Everything else —
// digesting, verifying, restoring, reporting — never learns there is more than one client,
// which is the property worth protecting as more are added.
type agent struct {
	// Name is what a person types after --agent.
	Name string
	// HomeDir is the directory under $HOME, e.g. ".claude".
	HomeDir string
	// HomeEnv is the variable that overrides it, empty when the client has none.
	HomeEnv string
	// HookConfig is the file hooks are written into, relative to the home. Both clients
	// use the same JSON shape — {"hooks": {"<Event>": [{"matcher": …, "hooks": […]}]}} —
	// so only the path differs, and the merge that writes it is shared.
	HookConfig string
	// SkillDir is where loose skills live, relative to the home.
	SkillDir string
	// Hooks are the moments this client offers that are worth taking.
	Hooks func(executable string) []hookSpec
	// AfterInstall is what the person still has to do in the client itself. Empty when
	// writing the file is the whole of it.
	//
	// It exists because Codex reviews hooks before it runs them, and a tool that wrote the
	// entry and said "installed" would leave somebody believing they were protected by a
	// hook sitting untrusted. The state this project exists to prevent is "looks
	// configured, is not running", and shipping it in our own installer would be
	// remarkable.
	AfterInstall string
}

// agents are the clients skillctl knows how to configure.
//
// Verified against the installed clients rather than their documentation: Codex CLI 0.149.1
// reports the same hook event names, accepts the same hook JSON, and keeps its plugin cache
// at ~/.codex/plugins/cache/<marketplace>/<plugin>/<version>. A client whose layout is
// merely similar does not belong in this table — the point of it is that everything below
// the table can stay ignorant of which client it is serving.
var agents = []agent{
	{
		Name: "claude", HomeDir: ".claude", HomeEnv: "CLAUDE_CONFIG_DIR",
		HookConfig: "settings.json", SkillDir: "skills",
		Hooks: claudeHooks,
	},
	{
		Name: "codex", HomeDir: ".codex", HomeEnv: "",
		// A dedicated file rather than a key in the client's settings: Codex reads hooks
		// from ~/.codex/hooks.json, and writing them into config.toml instead would be
		// configuration nobody reads.
		HookConfig: "hooks.json", SkillDir: "skills",
		Hooks: codexHooks,
		// Codex records a trusted_hash per hook in config.toml under [hooks.state] and
		// asks before running one it has not seen. Writing that hash from here would be
		// this tool granting itself execution inside another tool, past the review that
		// client added deliberately — so it is left for the person, and named instead of
		// worked around.
		AfterInstall: "Codex reviews hooks before it runs them. The next time it starts it " +
			"will ask you to trust this one; until you do, nothing is checked.\n" +
			"Approve it there rather than with --dangerously-bypass-hook-trust, which " +
			"turns off the review for every hook, not this one.",
	},
}

func lookupAgent(name string) (agent, error) {
	for _, known := range agents {
		if known.Name == name {
			return known, nil
		}
	}
	var names []string
	for _, known := range agents {
		names = append(names, known.Name)
	}
	sort.Strings(names)
	return agent{}, fmt.Errorf("unknown agent %q; skillctl knows %s",
		name, strings.Join(names, " and "))
}

// Home is where this client keeps its plugins on this machine.
func (a agent) Home() string {
	if a.HomeEnv != "" {
		if override := os.Getenv(a.HomeEnv); override != "" {
			return override
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return a.HomeDir
	}
	return filepath.Join(home, a.HomeDir)
}

// HookConfigPath is the file this client reads its hooks from.
func (a agent) HookConfigPath() string { return filepath.Join(a.Home(), a.HookConfig) }

// resolveAgentHome answers which directory a command should check.
//
// An explicit path always wins, because someone checking a machine that is not theirs —
// an image being built, a colleague's home restored from backup — is a real thing to do
// and must not require the client to be installed here at all.
func resolveAgentHome(agentName, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	known, err := lookupAgent(agentName)
	if err != nil {
		return "", err
	}
	return known.Home(), nil
}

// claudeHooks are the moments Claude Code offers.
//
// SessionStart reports what changed while nobody was looking. It cannot refuse anything —
// the documented behaviour is that its output is shown to the user only — so it is an
// awareness notice and nothing more.
//
// The per-skill check that can refuse (PreToolUse on the Skill tool) ships in the plugin
// rather than here, because a hook that fires on every skill invocation is a change to
// someone's client that should arrive with the thing they installed deliberately.
func claudeHooks(executable string) []hookSpec {
	return []hookSpec{{
		Event: "SessionStart", Matcher: "", Command: executable + " hook session-start",
		Why: "restores any centrally managed skill changed here, and says so",
	}}
}

// codexHooks are the moments Codex CLI offers, and there is deliberately one.
//
// Codex does not route a skill through a tool call. It lists every available skill — name,
// description and path — in the developer message it builds when the session starts, and the
// model then reads the SKILL.md itself with an ordinary file read. So there is no PreToolUse
// matcher that means "a skill is about to be loaded", and claiming one would be a hook that
// never fires.
//
// That is less of a loss than it looks. Because the list is built at session start, a
// SessionStart hook runs before the model has seen a single skill — so the bytes are put
// back before they can become instructions, rather than in the moment between. The weaker
// half is the same weakness as everywhere else: a session already under way is not
// re-checked.
func codexHooks(executable string) []hookSpec {
	return []hookSpec{{
		Event: "SessionStart", Matcher: "", Command: executable + " hook session-start --agent codex",
		Why: "restores any centrally managed skill changed here, before the session's skill list is built",
	}}
}
