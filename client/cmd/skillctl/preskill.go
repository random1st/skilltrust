package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
	"github.com/random1st/skilltrust/client/internal/skillmd"
)

// preToolUse is the part of the client's hook payload this needs. Everything else is
// ignored rather than modelled: a hook that fails to parse fields it does not use is a hook
// that breaks on the next release of the client.
type preToolUse struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Skill string `json:"skill"`
	} `json:"tool_input"`
}

// exitDeny is the exit code a PreToolUse hook uses to block the tool call.
const exitDeny = 2

// runHookPreSkill checks one skill immediately before its instructions are loaded.
//
// This is the moment that matters. A session-start report tells you what changed while you
// were away; this runs between "the model asked for this skill" and "this skill's prose is
// in the context window being followed with your credentials", and it is the only hook event
// here that can refuse.
//
// It is still not enforcement. Whoever can edit a skill can edit the settings entry that
// calls this, and the client documents that a hook which times out does not block. The claim
// is a check at the right moment, not a gate that cannot be walked around.
func runHookPreSkill(args []string) int {
	flags := flag.NewFlagSet("hook pre-skill", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl hook pre-skill [flags]\n\n"+
			"Reads a PreToolUse payload on stdin and checks the named skill against its\n"+
			"signed approval. Intended for a client hook, not for typing.\n\n"+
			"Exit codes: %d allow, %d deny (only with --strict).\n\nFlags:\n",
			exitClean, exitDeny)
		flags.PrintDefaults()
	}

	strict := flags.Bool("strict", false,
		"deny the skill when it does not match its approval, instead of warning")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return allow()
	}
	var payload preToolUse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return allow()
	}

	name := payload.ToolInput.Skill
	if name == "" {
		return allow()
	}

	result, root, found := checkSkill(name)
	if !found {
		// Nothing on this machine records what this skill should be — it is very often a
		// plugin skill living outside the trees under management. Refusing it would make
		// the tool an obstacle to everything it does not know about, which is how a check
		// gets uninstalled.
		return allow()
	}

	switch result.Status {
	case lockfile.StatusMatched:
		return allow()
	case lockfile.StatusAdded:
		return allow()
	}

	fmt.Fprintf(os.Stderr, "skillctl: %q does not match the bytes that were approved\n", name)
	fmt.Fprintf(os.Stderr, "  %s\n", filepath.Join(root, result.Path))
	if result.ApprovedBy != "" {
		fmt.Fprintf(os.Stderr, "  approved by %s\n", result.ApprovedBy)
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", expectedLabel(result.PinnedBy), result.Expected)
	fmt.Fprintf(os.Stderr, "  on disk   %s\n", result.Actual)
	for _, change := range result.Changes {
		fmt.Fprintf(os.Stderr, "    %-12s %s\n", change.Change, change.Path)
	}
	fmt.Fprintf(os.Stderr, "  re-approve with: skillctl setup\n")

	if *strict {
		return exitDeny
	}
	return exitClean
}

// allow is spelled out so every path that lets a skill through is visible as a decision
// rather than as a function running off its end.
func allow() int { return exitClean }

// checkSkill finds a skill by the name a client used and verifies just that one directory.
//
// Only the named skill is digested, not the whole tree: this runs on the critical path of
// every skill invocation, and a check that costs a full tree walk is one that gets disabled
// for being slow.
func checkSkill(name string) (lockfile.Result, string, bool) {
	// Plugin skills arrive as "plugin:skill". The bare name is what SKILL.md declares.
	candidates := []string{name}
	if _, suffix, found := strings.Cut(name, ":"); found && suffix != "" {
		candidates = append(candidates, suffix)
	}

	roots, err := resolveSkillRoots("")
	if err != nil {
		return lockfile.Result{}, "", false
	}

	for _, root := range roots {
		records, _, err := loadRecords(root)
		if err != nil {
			continue
		}
		for _, candidate := range candidates {
			directory, ok := findSkillDirectory(root, candidate)
			if !ok {
				continue
			}
			result, ok := verifyOne(root, directory, candidate, records)
			if ok {
				return result, root, true
			}
		}
	}
	return lockfile.Result{}, "", false
}

// findSkillDirectory locates the directory whose SKILL.md declares this name.
func findSkillDirectory(root, name string) (string, bool) {
	directories, _ := lint.Discover(root, lint.Options{})
	for _, directory := range directories {
		if declared, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name(); declared == name {
			return directory, true
		}
	}
	return "", false
}

// verifyOne compares one skill directory against whichever record covers it.
func verifyOne(root, directory, name string, records lockfile.Records) (lockfile.Result, bool) {
	built, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		return lockfile.Result{
			Name: name, Path: relativeOr(directory, root),
			Status: lockfile.StatusUnreadable, Message: err.Error(),
		}, true
	}

	result := lockfile.Result{
		Name: name, Path: relativeOr(directory, root), Actual: built.Digest,
	}

	if approval, ok := records.Notarized[name]; ok {
		result.PinnedBy, result.Expected = lockfile.PinnedByNotarization, approval.Digest
		result.ApprovedBy = approval.ApprovedBy
	} else if records.Lock != nil {
		for _, entry := range records.Lock.Skills {
			if entry.Name != name {
				continue
			}
			result.PinnedBy, result.Expected = lockfile.PinnedByLock, entry.Digest
			break
		}
	}
	if result.Expected == "" {
		return lockfile.Result{}, false
	}

	if result.Expected == built.Digest {
		result.Status = lockfile.StatusMatched
	} else {
		result.Status = lockfile.StatusModified
	}
	return result, true
}
