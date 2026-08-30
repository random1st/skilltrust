package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// An agent is a client that reads skills on this machine and can be asked to check them
// before it runs.
//
// Two things were once assumed of every client and only one of them held. The first is a
// directory of loose skills, which all three have. The second is a plugin cache laid out as
// <home>/plugins/cache/<marketplace>/<plugin>/<version> fed by a signed marketplace — Claude
// Code and Codex CLI both have it, in the same shapes, `.claude-plugin/plugin.json` and all,
// and Cursor has neither a marketplace nor that tree. So the two capabilities are separate
// fields rather than one notion of "supported", and a client can be known here for its skill
// directories alone.
//
// What differs between clients is a home directory, the file hooks are configured in, which
// moments that client offers, and whether anything centrally managed lives there. Those are
// what this type holds. Everything else — digesting, verifying, restoring, reporting — never
// learns there is more than one client, which is the property worth protecting as more are
// added.
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
	// ExtraRoots finds skill directories this client reads that no fixed path names,
	// given one base to look under — the working directory or the home. Nil for a client
	// whose skills are only ever in SkillDir.
	//
	// It exists because Antigravity CLI lets a repository register skills anywhere through
	// a skills.json, so the set of directories it reads is not knowable from a table. A
	// scanner that reported on SkillDir alone would describe a different machine than the
	// agent runs on, and would do it silently.
	ExtraRoots func(base string) []string
	// Managed reports whether this client installs plugins from a marketplace into
	// <home>/plugins/cache, which is the only tree reconciling can act on.
	//
	// False means every skilltrust command that restores or revokes has nothing to work
	// with here, and must say so instead of running and finding nothing.
	Managed bool
	// Hooks are the moments this client offers that are worth taking, and may be nil when
	// there is nothing worth checking at any of them.
	Hooks func(executable string) []hookSpec
	// NoHooksBecause is required whenever Hooks is nil, and is what someone who asked to
	// install one is told. "Nothing to install" on its own reads as a bug in this tool
	// rather than a fact about their client.
	NoHooksBecause string
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
		Managed: true, Hooks: claudeHooks,
	},
	{
		Name: "codex", HomeDir: ".codex", HomeEnv: "",
		// A dedicated file rather than a key in the client's settings: Codex reads hooks
		// from ~/.codex/hooks.json, and writing them into config.toml instead would be
		// configuration nobody reads.
		HookConfig: "hooks.json", SkillDir: "skills",
		Managed: true, Hooks: codexHooks,
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
	{
		Name: "cursor", HomeDir: ".cursor", HomeEnv: "",
		HookConfig: "hooks.json", SkillDir: "skills",
		// Cursor installs nothing from a marketplace. It has no plugins/cache tree at all —
		// its skills are the ones written into ~/.cursor/skills or committed to a repo's
		// .cursor/skills, and there is no publisher whose signature they could be checked
		// against. So it is listed for its skill directories and nothing else, and Hooks is
		// deliberately nil: a sessionStart entry reconciling a cache that does not exist
		// would be a hook that never fires, which is the failure the Codex work refused to
		// ship and would be no better here.
		//
		// It is worth knowing what it does have, because the temptation is real. Cursor
		// offers a native sessionStart hook in ~/.cursor/hooks.json, and separately reads
		// Claude Code's ~/.claude/settings.json, translating SessionStart to its own
		// sessionStart and PreToolUse matchers Bash, Read, Write and Edit to its own. That
		// import is gated on claudeCodeHooksEnabled, which arrives in the server config
		// response rather than from any file here and defaults to off — so whether the hook
		// this tool wrote for Claude Code also runs in Cursor is not a fact this machine can
		// observe. Claiming it does would be a promise held by somebody else's feature flag.
		//
		// The one thing that is both true and useful: with third-party extensibility on, its
		// default, Cursor also loads ~/.claude/skills and ~/.codex/skills — directories
		// skillRoots already covers, so a machine scanned for Claude Code is largely
		// scanned for Cursor too.
		Managed: false, Hooks: nil,
		NoHooksBecause: "Cursor installs no plugins from a marketplace, so there is nothing " +
			"here for a check to put back or refuse.\n" +
			"Its skills are the ones in ~/.cursor/skills and a repository's .cursor/skills; " +
			"those are covered by skillctl lint, which reads them without a hook.\n" +
			"Cursor also loads ~/.claude/skills and ~/.codex/skills, so a machine set up for " +
			"either of those is already largely covered here.",
	},
	{
		Name: "antigravity", HomeDir: ".gemini", HomeEnv: "",
		// Its global customization root is ~/.gemini/config, which holds hooks.json,
		// mcp_config.json and skills/. Verified against agy 1.1.15's own strings rather
		// than the migration page, which names a different directory.
		HookConfig: filepath.Join("config", "hooks.json"),
		SkillDir:   filepath.Join("config", "skills"),
		ExtraRoots: antigravityRoots,
		// Antigravity has plugins, and they are not the plugins this tool reconciles.
		// `agy plugin install` accepts plugin@marketplace, but what lands on disk is
		// plugins/<name>/plugin.json inside a customization root — no marketplace in the
		// path, no version, and the manifest at the directory root rather than under
		// .claude-plugin. Reconciling keys on (marketplace, plugin, version) and could not
		// identify an installed copy here, so there is nothing for a check to put back.
		Managed: false, Hooks: nil,
		NoHooksBecause: "Antigravity installs plugins as plugins/<name>/ inside a " +
			"customization root, recording neither which marketplace they came from nor " +
			"which version, so there is nothing here a check could put back or refuse.\n" +
			"Its skills — .agents/skills, ~/.gemini/config/skills, and anything a " +
			"skills.json registers — are covered by skillctl lint, which reads them " +
			"without a hook.\n" +
			"It offers no session-start moment either: the events are PreToolUse, " +
			"PostToolUse, PreInvocation, PostInvocation and Stop, and the first two run on " +
			"every tool call rather than once.",
	},
}

// antigravityRoots finds the skill directories a skills.json registers under base.
//
// Antigravity discovers skills from `.agents/skills` and `~/.gemini/config/skills`, both of
// which the table already covers — and from `entries[].path` in a skills.json, which may
// point anywhere: absolute, ~/-relative, or relative to the repository root. A team that
// keeps its skills in tools/agents/skills and registers them this way is the documented
// way to share them, so a scanner that only knew the fixed paths would report on a machine
// nobody is running.
//
// include_only and exclude are deliberately not applied. They are regular expressions over
// skill directory names inside a root, and this returns roots; honouring them would mean
// carrying per-root filters through every caller. The cost of ignoring them is scanning a
// skill Antigravity would skip, which is noise. The cost of the other error — missing a
// root — is a silent gap, and between the two the choice is not close.
func antigravityRoots(base string) []string {
	var found []string
	for _, config := range []string{
		filepath.Join(base, ".agents", "skills.json"),
		filepath.Join(base, ".gemini", "config", "skills.json"),
	} {
		found = append(found, readSkillsConfig(config, base, map[string]bool{}, 0)...)
	}
	return found
}

// readSkillsConfig resolves one skills.json, following the configs it inherits.
//
// Inheritance is followed rather than skipped: a shared config is how an organisation
// distributes the paths, so stopping at the first file would miss exactly the machines with
// the most skills on them. depth and seen bound it — a config that inherits itself is a
// hang in a command that runs at session start, and a malformed file must cost nothing.
func readSkillsConfig(path, base string, seen map[string]bool, depth int) []string {
	const maxDepth = 8
	resolved, err := filepath.Abs(path)
	if err != nil || depth > maxDepth || seen[resolved] {
		return nil
	}
	seen[resolved] = true

	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil
	}
	var document struct {
		Inherits []struct {
			Path string `json:"path"`
		} `json:"inherits"`
		Entries []struct {
			Path string `json:"path"`
		} `json:"entries"`
	}
	// A skills.json this cannot parse is Antigravity's problem to report, not ours to fail
	// on: every command that walks skill roots would otherwise stop on somebody's typo.
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil
	}

	var roots []string
	for _, parent := range document.Inherits {
		if parent.Path == "" {
			continue
		}
		roots = append(roots, readSkillsConfig(
			resolveConfigPath(parent.Path, base), base, seen, depth+1)...)
	}
	for _, entry := range document.Entries {
		if entry.Path == "" {
			continue
		}
		candidate := resolveConfigPath(entry.Path, base)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			roots = append(roots, candidate)
		}
	}
	return roots
}

// resolveConfigPath applies the three rules Antigravity documents: absolute stays absolute,
// ~/ is the home directory, and anything else is relative to the repository root — which
// here is the base the config was found under.
func resolveConfigPath(path, base string) string {
	switch {
	case filepath.IsAbs(path):
		return path
	case strings.HasPrefix(path, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	default:
		return filepath.Join(base, path)
	}
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
	last := len(names) - 1
	return agent{}, fmt.Errorf("unknown agent %q; skillctl knows %s and %s",
		name, strings.Join(names[:last], ", "), names[last])
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
