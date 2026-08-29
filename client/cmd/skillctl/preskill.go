package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
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
	flags := flag.NewFlagSet("hook pre-skill", flag.ContinueOnError)
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

	if err := parseArgs(flags, args); err != nil {
		return exitClean
	}
	home := *claudeHome
	if home == "" {
		home = marketplace.DefaultClaudeHome()
	}

	plugin := pluginFromPayload(os.Stdin)
	if plugin == "" {
		// An unnamespaced skill is a personal or project one. Claude Code namespaces every
		// plugin skill as plugin:skill, so the absence of a prefix is itself the answer.
		return exitClean
	}

	subscriptions, err := loadSubscriptions()
	if err != nil || len(subscriptions) == 0 {
		return exitClean
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return exitClean
	}

	// The hook is the only check most machines ever run, so an adoption the hook does not
	// read is an adoption that does not exist: sync would honour it and then every session
	// would quietly put the published bytes back. An unreadable file adopts nothing here
	// too — it must not become "accept everything" on the path that runs unattended.
	adopted, err := marketplace.LoadAdoptions(defaultAdoptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		adopted = marketplace.Adoptions{}
	}

	now := time.Now().UTC()
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, now)
		if err != nil {
			// Refuse only over a marketplace that actually claims this plugin: a machine
			// whose unrelated catalog expired must not lose everything else it runs.
			if claimsPlugin(subscription, plugin) {
				fmt.Fprintf(os.Stderr, "skillctl: %q comes from %s, which this machine "+
					"cannot verify right now, so it was not loaded: %v\n"+
					"  fix with: skillctl sync\n", plugin, subscription.Name, err)
				if *permissive {
					return exitClean
				}
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
			return decide(result, *permissive)
		}
	}
	return exitClean
}

func decide(result marketplace.Result, permissive bool) int {
	switch result.Outcome {
	case marketplace.OutcomeRevoked:
		fmt.Fprintf(os.Stderr, "skillctl: %q has been revoked by %s and was not loaded\n",
			result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", result.Detail)
		}
		return exitDeny

	case marketplace.OutcomeAdapted:
		// Said once per session, quietly, and it loads. A person who chose to keep their
		// own copy should be reminded that they did — silence here would let an adoption
		// made months ago be mistaken for the published skill — but this is not a warning
		// and must not read like one.
		fmt.Fprintf(os.Stderr, "skillctl: %q is your own modified copy (%s)\n",
			result.Plugin, result.Adapted)
		return exitClean

	case marketplace.OutcomeRestored:
		fmt.Fprintf(os.Stderr, "skillctl: %q had been changed on this machine and was "+
			"restored to what %s publishes before it loaded\n", result.Plugin, result.Marketplace)
		if result.Quarantine != "" {
			fmt.Fprintf(os.Stderr, "  what was there: %s\n", result.Quarantine)
		}
		fmt.Fprintf(os.Stderr, "  to keep your version instead: skillctl adopt %s --because \"...\"\n",
			result.Plugin)
		return exitClean

	case marketplace.OutcomeUnverifiable, marketplace.OutcomeChanged:
		fmt.Fprintf(os.Stderr, "skillctl: %q is signed by %s but could not be put back, "+
			"so it was not loaded", result.Plugin, result.Marketplace)
		if result.Detail != "" {
			fmt.Fprintf(os.Stderr, ": %s", result.Detail)
		}
		fmt.Fprintln(os.Stderr)
		if permissive {
			return exitClean
		}
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
