package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Home is where skillctl keeps the things a user should not have to name: the signing key,
// the pinned keys, the revocation catalog and its state.
//
// Every one of those started life as a required flag pointing at the working directory,
// which meant the common commands only worked from one place and the manual was a list of
// paths. Defaults belong under the hood; the flags remain for anyone who needs them.
func Home() string {
	if override := os.Getenv("SKILLTRUST_HOME"); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".skilltrust"
	}
	return filepath.Join(home, ".skilltrust")
}

// Paths inside the home.
func homePath(name string) string { return filepath.Join(Home(), name) }

func defaultSigningKey() string  { return homePath("signer.key") }
func defaultPublicKey() string   { return homePath("signer.pub") }
func defaultTrustedKeys() string { return homePath("trusted-keys.json") }
func defaultCatalog() string     { return homePath("catalog.json") }
func defaultAdoptions() string   { return homePath("adopted.json") }

// skillRoots are the conventional locations, project before user. A client looks in all of
// them, so a tool that reports on one and stays quiet about the others is describing a
// different machine than the one the agent is running on.
func skillRoots() []string {
	var roots []string
	for _, base := range baseDirectories() {
		// `.agents/skills` first: it is the cross-client location, and Codex and Amp both
		// read it alongside their own. The per-client ones follow, one per known agent, so
		// adding a client to the table in agents.go is the whole change.
		suffixes := []string{filepath.Join(".agents", "skills")}
		for _, known := range agents {
			suffixes = append(suffixes, filepath.Join(known.HomeDir, known.SkillDir))
		}
		for _, suffix := range suffixes {
			candidate := filepath.Join(base, suffix)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				roots = append(roots, candidate)
			}
		}
		// And the directories no fixed path can name. Antigravity CLI lets a repository
		// register skills anywhere through a skills.json, so for that client the set is a
		// property of the machine rather than of this table. Asking the client keeps the
		// knowledge beside the client, which is the whole point of the table.
		for _, known := range agents {
			if known.ExtraRoots == nil {
				continue
			}
			roots = append(roots, known.ExtraRoots(base)...)
		}
	}
	return roots
}

// baseDirectories are the places a client would look for project and user configuration.
//
// The working directory is not enough, and this was wrong for as long as the scanner has
// existed. Every client here searches upwards: Claude Code, Codex, Cursor and Antigravity all
// walk from the directory they were started in towards the repository root looking for
// `.claude`, `.cursor` or `.agents`. Anyone who ran a check from inside `src/` or `server/` —
// which is where people work — was told their machine was clean by a command that never
// looked at the project's own skills directory one level up.
//
// The walk stops at the repository root, because that is where the clients stop, and going
// further would start reporting a neighbouring checkout's skills as this one's. A directory
// that is in no repository contributes itself alone, which is what happened before.
func baseDirectories() []string {
	var bases []string
	if working, err := os.Getwd(); err == nil {
		bases = append(bases, workingAncestors(working)...)
	}
	if home, err := os.UserHomeDir(); err == nil {
		bases = append(bases, home)
	}
	return bases
}

// maxAncestors bounds the climb. Nothing legitimate is sixty directories deep, and a scan
// must not walk an unbounded path because a mount went strange or a symlink loops.
const maxAncestors = 64

// workingAncestors returns the working directory and everything above it up to and including
// the repository root, nearest first.
func workingAncestors(working string) []string {
	root, found := repositoryRoot(working)
	if !found {
		return []string{working}
	}
	var bases []string
	for current := working; len(bases) < maxAncestors; {
		bases = append(bases, current)
		if current == root {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return bases
}

// repositoryRoot finds the directory holding .git, which is where every client stops.
//
// `.git` is tested with Stat rather than as a directory: a worktree or a submodule has a
// file there, and treating those as "not a repository" would quietly turn the walk off for
// exactly the checkouts people use for parallel work.
func repositoryRoot(start string) (string, bool) {
	for current, steps := start, 0; steps < maxAncestors; steps++ {
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			return current, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
	return "", false
}

// resolveSkillRoots returns every location a command with no path argument should cover.
//
// A client reads all of them, so summarising one and mentioning the others in a footnote
// describes a different machine than the agent is running on. Picking one was how the
// scanner previously reported on an eighth of a tree and was believed.
func resolveSkillRoots(explicit string) ([]string, error) {
	if explicit != "" {
		resolved, err := resolveSkillRoot(explicit)
		if err != nil {
			return nil, err
		}
		return []string{resolved}, nil
	}

	roots := dedupeByResolvedPath(skillRoots())
	if len(roots) == 0 {
		return nil, noSkillsError()
	}
	return roots, nil
}

// dedupeByResolvedPath collapses paths that name the same directory, and returns them
// resolved.
//
// The conventional locations overlap constantly: ~/.claude/skills is usually a symlink to
// ~/.agents/skills, and running from your home directory makes the project and user
// candidates the same paths again. Without this the hook verified one tree four times and
// reported 388 skills where there are 97, while lint warned about "3 other skills
// directories" that do not exist. Both are the alert-fatigue failure this tool avoids
// elsewhere: a number nobody can reconcile is a number nobody reads.
func dedupeByResolvedPath(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	var unique []string
	for _, path := range paths {
		resolved, _, err := resolvePath(path)
		if err != nil {
			continue
		}
		if _, repeat := seen[resolved]; repeat {
			continue
		}
		seen[resolved] = struct{}{}
		unique = append(unique, resolved)
	}
	return unique
}

// noSkillsError names every place that was actually searched.
//
// Built from the agents table rather than written out, because it was written out: it still
// said ".agents/skills and .claude/skills" three clients after those stopped being the whole
// list, and told people the search covered "here and under your home directory" after it had
// started climbing to the repository root. An error that misdescribes where a tool looked
// sends someone to check a directory that was already checked.
func noSkillsError() error {
	looked := []string{filepath.Join(".agents", "skills")}
	for _, known := range agents {
		looked = append(looked, filepath.ToSlash(filepath.Join(known.HomeDir, known.SkillDir)))
	}
	return fmt.Errorf("no skills directory found; looked for %s in this directory, in every "+
		"directory up to the repository root, and under your home directory. Pass a path to "+
		"scan somewhere else", strings.Join(looked, ", "))
}

// resolveSkillRoot picks what a command with no path argument should look at.
//
// It reports which directory it chose rather than choosing silently: a scanner that decides
// for you and does not say so produces a clean report about somewhere you were not asking
// about, and that report gets believed.
func resolveSkillRoot(explicit string) (string, error) {
	if explicit != "" {
		resolved, note, err := resolvePath(explicit)
		if err != nil {
			return "", err
		}
		if note != "" {
			fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
		}
		return resolved, nil
	}

	// Deduplicate before counting: the alternatives are only worth mentioning when they are
	// genuinely different trees, and most machines have several names for one.
	roots := dedupeByResolvedPath(skillRoots())
	if len(roots) == 0 {
		return "", noSkillsError()
	}

	fmt.Fprintf(os.Stderr, "skillctl: scanning %s\n", roots[0])
	if others := len(roots) - 1; others > 0 {
		// The verb agrees too. "1 other skills directory exist" is the same class of thing
		// as "1 machines", which the plural helper below exists to avoid: a number rendered
		// carelessly is a number the reader stops trusting, in a report whose only value is
		// being trusted about numbers.
		fmt.Fprintf(os.Stderr, "skillctl: %d other skills director%s %s not scanned; pass a "+
			"path to scan one of them\n",
			others, plural(others, "y", "ies"), plural(others, "was", "were"))
	}
	return roots[0], nil
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

// gitIdentity is a sensible default for who approved something. Requiring --as on every
// signature is the sort of friction that gets scripted around with a placeholder, and a
// placeholder in an approval record is worse than a real address that is merely imprecise.
func gitIdentity() string {
	command := exec.Command("git", "config", "--get", "user.email")
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// relativeOr renders a path against a root when it is inside it, so reports name the skill
// rather than repeating a long absolute prefix on every line.
func relativeOr(path, root string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return relative
}
