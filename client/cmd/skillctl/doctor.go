package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/random1st/skilltrust/attest"
)

// An inventory is a current observation, not a saved signed check or a claim that
// session hooks are installed. Cached plugin versions may include inactive copies.
type skillInventory struct {
	Scope       string             `json:"scope"`
	Roots       []string           `json:"roots"`
	CheckedAt   time.Time          `json:"checked_at"`
	Found       int                `json:"found"`
	Verified    int                `json:"verified"`
	Changed     int                `json:"changed"`
	Unapproved  int                `json:"unapproved"`
	Errors      int                `json:"errors"`
	TrustedKeys int                `json:"trusted_keys"`
	Details     string             `json:"details,omitempty"`
	Skills      []skillObservation `json:"skills"`
}

// Tests inject owned roots without changing HOME or discovering the host's skills.
var doctorRootCandidates = func() []string { return installedSkillRootCandidates(baseDirectories()) }

func installedSkillRootCandidates(bases []string) []string {
	roots := skillRootCandidates(bases)
	for _, known := range agents {
		// Home honours an agent's supported configuration override, where present.
		roots = append(roots, filepath.Join(known.Home(), known.SkillDir))
		if known.Layout == layoutPluginCache {
			roots = append(roots, filepath.Join(known.Home(), "plugins", "cache"))
		}
	}
	return roots
}

func runDoctor(args []string) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s doctor [--json] [--absolute-commands]\n\n"+
			"Check installed skills and show the next command. No account is required.\n"+
			"With a followed catalog, performs the same check as status --refresh.\n"+
			"Otherwise, reads local skill directories and plugin caches against existing\n"+
			"approvals, without creating keys, approving, installing or restoring skills.\n\nFlags:\n", commandName())
		flags.PrintDefaults()
	}
	asJSON := flags.Bool("json", false, "return the current verdict and next command as JSON")
	absoluteCommands := flags.Bool("absolute-commands", false, "use this executable's absolute path in next commands (for plugin runtimes outside PATH)")
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		return fail(fmt.Errorf("doctor takes no positional arguments"))
	}
	out := collectMachineStatus(true)
	if out.NextAction != nil {
		out.NextAction.Detail = strings.ReplaceAll(out.NextAction.Detail, "skillctl ", commandName()+" ")
	}
	if *absoluteCommands {
		executable, err := os.Executable()
		if err != nil {
			return fail(fmt.Errorf("locate Axela for the next command: %w", err))
		}
		useExecutable := func(command []string) {
			if len(command) > 0 && command[0] == commandName() {
				command[0] = executable
			}
		}
		useExecutable(out.NextCommand)
		for _, saved := range out.SavedChanges {
			useExecutable(saved.NextCommand)
		}
	}
	return writeMachineStatus(out, *asJSON)
}

// Reuse the attestation verifier for the first verdict. Missing trust is an
// ordinary first-run state; malformed trust and unreadable skills remain errors.
func inspectInstalledSkills(candidates []string) machineStatus {
	var details bytes.Buffer
	roots := []string{}
	seen := map[string]bool{}
	rootErrors := 0
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		// Lstat first keeps a broken, existing symlink from looking like absence.
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			err = fmt.Errorf("%s is not a skills directory", candidate)
		}
		var resolved string
		if err == nil {
			resolved, err = filepath.EvalSymlinks(candidate)
		}
		if err != nil {
			rootErrors++
			fmt.Fprintf(&details, "skillctl: %v\n", err)
			continue
		}
		if resolved != candidate && seen[resolved] {
			continue
		}
		seen[resolved] = true
		roots = append(roots, resolved)
	}

	keys, keyErr := attest.PinnedKeys(defaultTrustedKeys())
	// PinnedKeys treats a missing target as no pins. An existing broken symlink
	// is a damaged trust configuration, not permission to start trusting anew.
	if info, err := os.Lstat(defaultTrustedKeys()); err == nil && info.Mode()&os.ModeSymlink != 0 && keyErr == nil {
		_, keyErr = os.Stat(defaultTrustedKeys())
	}
	var public []ed25519.PublicKey
	for _, key := range keys {
		public = append(public, key)
	}
	if keyErr != nil {
		fmt.Fprintf(&details, "skillctl: pinned keys could not be read: %v\n", keyErr)
	}
	summary, _, _ := inspectSkillRoots(attest.NewTrustedKeys(public...), true, roots, &details, &details)
	summary.Errors += rootErrors
	if keyErr != nil {
		summary.Errors++
	}
	inventory := &skillInventory{
		Scope: "local_skill_directories_and_plugin_caches", Roots: roots, CheckedAt: summary.CheckedAt,
		Found: summary.Found, Verified: summary.Verified, Changed: summary.Changed,
		Unapproved: summary.Unapproved, Errors: summary.Errors, TrustedKeys: len(public),
		Details: strings.TrimSpace(details.String()),
		Skills:  summary.Observations,
	}
	out := machineStatus{Version: 1, Status: "needs_attention", Hooks: []machineHook{}, Inventory: inventory,
		NextAction:  &nextAction{"subscribe", "user", "Ask your publisher for the signed repository and its public key through a trusted channel; subscription help shows the required inputs. No account is required."},
		NextCommand: []string{commandName(), "subscribe", "--help"}}
	switch {
	case keyErr != nil:
		out.Title = "The pinned keys could not be read"
		out.NextAction = &nextAction{"inspect_trust", "user", "Inspect the existing pinned-key file and correct the reported error; keep the established publisher keys."}
		out.NextCommand = []string{commandName(), "trust"}
	case summary.Errors > 0:
		out.Title = "Some skills or approvals could not be checked"
		out.NextAction = &nextAction{"inspect_skills", "user", "Review the read errors above; unreadable skills and approvals have not passed verification."}
		out.NextCommand = []string{commandName(), "doctor", "--json"}
		if summary.FirstIssue != "" {
			out.NextCommand = []string{commandName(), "digest", summary.FirstIssue}
		}
	case summary.Changed > 0:
		out.Title = "Approved skills have changed"
		out.NextAction = &nextAction{"review_changes", "user", "Review the changed directory against the approved digest above. Print its current digest; your files have been preserved."}
		out.NextCommand = []string{commandName(), "digest", summary.FirstIssue}
	case summary.Found == 0:
		out.Title = "No installed skills were found in the checked locations"
	case summary.Unapproved > 0:
		out.Title = "Some installed skills have no trusted approval"
		if len(public) == 0 {
			out.Title = "Skills found; no publisher keys are pinned"
		}
		out.NextAction = &nextAction{"review_skill", "user", "Review the content of this unapproved skill. Lint reports risk indicators; it does not approve the skill."}
		for _, skill := range inventory.Skills {
			if skill.Verdict == "unapproved" {
				out.NextCommand = []string{commandName(), "lint", skill.Path}
				break
			}
		}
	case summary.Verified == summary.Found:
		out.Status, out.Title = "approvals_checked", "Installed skill bytes match their trusted approvals"
		out.NextAction, out.NextCommand = nil, nil
	}
	return out
}

// JSON carries argv so callers never need to parse prose. The terminal form is
// quoted for a POSIX shell, including paths containing whitespace or metacharacters.
func nextCommandText(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		plain := arg != ""
		for _, r := range arg {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./:@%+=,-", r)) {
				plain = false
				break
			}
		}
		quoted[i] = arg
		if !plain {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
	}
	return strings.Join(quoted, " ")
}

func printNextCommand(args []string) {
	command := nextCommandText(args)
	if strings.IndexFunc(command, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		fmt.Printf("Next command arguments (escaped): %q\n", args)
		return
	}
	fmt.Printf("Run: %s\n", command)
}
