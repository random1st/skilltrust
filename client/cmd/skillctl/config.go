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
	}
	return roots
}

func baseDirectories() []string {
	var bases []string
	if working, err := os.Getwd(); err == nil {
		bases = append(bases, working)
	}
	if home, err := os.UserHomeDir(); err == nil {
		bases = append(bases, home)
	}
	return bases
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

func noSkillsError() error {
	return fmt.Errorf("no skills directory found; looked for .agents/skills and " +
		".claude/skills here and under your home directory. Pass a path to scan somewhere else")
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
	if len(roots) > 1 {
		fmt.Fprintf(os.Stderr, "skillctl: %d other skills director%s exist; pass a path "+
			"to scan one of them\n", len(roots)-1, plural(len(roots)-1, "y", "ies"))
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
