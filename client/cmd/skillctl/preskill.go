package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
)

// exitDeny is the exit code a PreToolUse hook uses to refuse the tool call.
const exitDeny = 2

// preToolUse is the part of the client's payload this needs. Everything else is ignored
// rather than modelled: a hook that fails on fields it does not use breaks on the next
// release of the client.
type preToolUse struct {
	ToolInput struct {
		Skill string `json:"skill"`
	} `json:"tool_input"`
}

// runHookPreSkill checks one plugin in the moment before a skill it ships is loaded.
//
// The session hook covers what changed while nobody was looking; it cannot cover an edit
// made after it ran, and a session is long. Between "an agent wrote into the plugin cache"
// and "that plugin's prose is being followed with production credentials" there is nothing
// else, and PreToolUse is the only event here that can refuse.
//
// It restores rather than refusing where restoring is possible, so the agent goes on to read
// the published bytes instead of the edited ones. Refusal is kept for the cases with no
// correct bytes to hand over: a revoked plugin, or a marketplace this machine cannot verify.
func runHookPreSkill(args []string) int {
	return runHookPreSkillTo(args, os.Stdin, os.Stdout, os.Stderr)
}

func runHookPreSkillTo(args []string, input io.Reader, output, diagnostics io.Writer) (code int) {
	flags := flag.NewFlagSet("hook pre-skill", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl hook pre-skill [flags]\n\n"+
			"Reads a PreToolUse payload on stdin. If the skill belongs to a signed plugin\n"+
			"that has been changed here, the plugin is put back before it loads; if it is\n"+
			"revoked or unverifiable, the call is refused. Skills outside a signed\n"+
			"marketplace are allowed without a word.\n\n"+
			"Exit codes: %d allow, %d refuse.\n\nFlags:\n", exitClean, exitDeny)
		flags.PrintDefaults()
	}

	claudeHome := flags.String("claude-home", "", "Claude Code directory (default ~/.claude)")
	permissive := flags.Bool("permissive", false,
		"warn instead of refusing when a signed plugin cannot be verified")
	claudeJSON := flags.Bool("claude-json", false, "return an allowed call's warning as Claude Code hook JSON")

	if err := parseArgs(flags, args); err != nil {
		if *claudeJSON {
			_ = writeClaudeHookJSON(output, "PreToolUse", flagOutput.String())
		} else {
			fmt.Fprint(diagnostics, flagOutput.String())
		}
		return exitClean
	}
	if *claudeJSON {
		var notice bytes.Buffer
		originalDiagnostics := diagnostics
		diagnostics = &notice
		defer func() {
			if code == exitClean {
				_ = writeClaudeHookJSON(output, "PreToolUse", notice.String())
			} else {
				// JSON does not substitute for the blocking exit code. Keep the
				// original deny contract for every Claude version we support.
				fmt.Fprint(originalDiagnostics, visibleHookText(notice.String()))
			}
		}()
	}
	home := *claudeHome
	if home == "" {
		home = marketplace.DefaultClaudeHome()
	}

	plugin := pluginFromPayload(input)
	if plugin == "" {
		// An unnamespaced skill is a personal or project one. Claude Code namespaces every
		// plugin skill as plugin:skill, so the absence of a prefix is itself the answer.
		return exitClean
	}

	subscriptions, err := loadSubscriptions()
	if err != nil || len(subscriptions) == 0 {
		if err != nil && *claudeJSON {
			fmt.Fprintf(diagnostics, "Axela: %q was not checked because subscriptions could not be read: %v. Run %s doctor.\n", plugin, err, commandName())
		}
		return exitClean
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		for _, subscription := range subscriptions {
			if (subscription.Access != "" || legacyAxelaSubscription(subscription)) && (claimsPlugin(subscription, plugin) || teamPluginInstalled(subscription, plugin, home)) {
				fmt.Fprintf(diagnostics, "Axela: %q could not be checked for current team access because pinned keys are unreadable. The skill was not loaded; run %s doctor.\n", plugin, commandName())
				return exitDeny
			}
		}
		if *claudeJSON {
			fmt.Fprintf(diagnostics, "Axela: %q was not checked because pinned keys could not be read: %v. Run %s doctor.\n", plugin, err, commandName())
		}
		return exitClean
	}

	// The hook is the only check most machines ever run, so an adoption the hook does not
	// read is an adoption that does not exist: sync would honour it and then every session
	// would quietly put the published bytes back. An unreadable file adopts nothing here
	// too — it must not become "accept everything" on the path that runs unattended.
	adopted, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil {
		fmt.Fprintf(diagnostics, "skillctl: %v\n", err)
		adopted = marketplace.Adoptions{}
	}

	now := time.Now().UTC()
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, now)
		team := subscription.Access != "" || legacyAxelaSubscription(subscription)
		claimed := claimsPlugin(subscription, plugin)
		if snapshot != nil {
			_, signed := snapshot.Publishes(plugin)
			claimed = claimed || signed
		}
		if team {
			claimed = claimed || teamPluginInstalled(subscription, plugin, home)
		}
		if team && claimed {
			ctx, cancel := refreshContext(3 * time.Second)
			snapshot, _, err = loadManagedSnapshot(ctx, subscription, trusted, now, ManagedCheckOptions{UpdateSource: true})
			cancel()
		}
		if err != nil {
			// Refuse only over a marketplace that actually claims this plugin: a machine
			// whose unrelated catalog expired must not lose everything else it runs.
			if claimed {
				fmt.Fprintf(diagnostics, "skillctl: %q comes from %s, which this machine "+
					"cannot verify right now: %v\n"+
					"  fix with: %s doctor\n", plugin, subscription.Name, err, commandName())
				if *permissive && !team {
					fmt.Fprintln(diagnostics, "  allowed by permissive mode; these bytes were not verified")
					return exitClean
				}
				fmt.Fprintln(diagnostics, "  the skill was not loaded")
				return exitDeny
			}
			continue
		}
		if _, signed := snapshot.Publishes(plugin); !signed {
			continue
		}

		for _, result := range marketplace.Reconcile(snapshot, marketplace.Options{
			ClaudeHome:     home,
			Adopted:        adopted,
			Source:         source.Path(catalogRoot(), subscription.Name),
			QuarantineRoot: quarantineRoot(),
			Restore:        true,
			Now:            now,
		}) {
			if result.Plugin != plugin {
				continue
			}
			return decideTo(result, *permissive, diagnostics)
		}
	}
	return exitClean
}

// Missing or edited source metadata cannot make an installed team plugin
// unrelated. This is a reason to demand authorization, never proof of trust.
func teamPluginInstalled(subscription Subscription, plugin, home string) bool {
	name := subscription.CatalogName
	if name == "" {
		name = subscription.Name
	}
	if !catalogNameOK.MatchString(name) || !catalogNameOK.MatchString(plugin) {
		return false
	}
	_, err := os.Lstat(filepath.Join(marketplace.CacheRoot(home), name, plugin))
	return !os.IsNotExist(err)
}

func decide(result marketplace.Result, permissive bool) int {
	return decideTo(result, permissive, os.Stderr)
}

func decideTo(result marketplace.Result, permissive bool, diagnostics io.Writer) int {
	switch result.Outcome {
	case marketplace.OutcomeRevoked:
		fmt.Fprintf(diagnostics, "skillctl: %q has been revoked by %s and was not loaded\n",
			result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Fprintf(diagnostics, "  %s\n", result.Detail)
		}
		return exitDeny

	case marketplace.OutcomeAdapted:
		// Said once per session, quietly, and it loads. A person who chose to keep their
		// own copy should be reminded that they did — silence here would let an adoption
		// made months ago be mistaken for the published skill — but this is not a warning
		// and must not read like one.
		fmt.Fprintf(diagnostics, "skillctl: %q is your own modified copy (%s)\n",
			result.Plugin, result.Adapted)
		return exitClean

	case marketplace.OutcomeRestored:
		fmt.Fprintf(diagnostics, "skillctl: %q had been changed on this machine and was "+
			"restored to what %s publishes before it loaded\n", result.Plugin, result.Marketplace)
		if result.Quarantine != "" {
			fmt.Fprintf(diagnostics, "  what was there: %q\n", result.Quarantine)
		}
		writeQuarantineNotice(diagnostics, result)
		return exitClean

	case marketplace.OutcomeUnverifiable, marketplace.OutcomeChanged:
		fmt.Fprintf(diagnostics, "skillctl: %q is signed by %s but could not be put back",
			result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Fprintf(diagnostics, ": %s", result.Detail)
		}
		fmt.Fprintln(diagnostics)
		if permissive {
			fmt.Fprintln(diagnostics, "  allowed by permissive mode; these bytes were not verified")
			return exitClean
		}
		fmt.Fprintln(diagnostics, "  the skill was not loaded")
		return exitDeny
	}
	return exitClean
}

// claimsPlugin reports whether a marketplace names this plugin, read without verification.
//
// Used only to decide whether an unverifiable marketplace is relevant, never to reach a
// verdict: the worst an attacker gains by editing the index is having their own plugin
// refused.
func claimsPlugin(subscription Subscription, plugin string) bool {
	manifest, err := marketplace.Load(source.Path(catalogRoot(), subscription.Name))
	if err != nil {
		return false
	}
	for _, entry := range manifest.Plugins {
		if entry.Name == plugin {
			return true
		}
	}
	return false
}

// pluginFromPayload returns the plugin a skill belongs to, or empty when it belongs to none.
func pluginFromPayload(reader io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		return ""
	}
	var payload preToolUse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	prefix, _, namespaced := strings.Cut(payload.ToolInput.Skill, ":")
	if !namespaced {
		return ""
	}
	return prefix
}
