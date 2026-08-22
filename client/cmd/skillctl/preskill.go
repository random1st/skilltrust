package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/catalog"
	"github.com/random1st/skilltrust/client/internal/fleet"
	"github.com/random1st/skilltrust/client/internal/source"
)

// exitDeny is the exit code a PreToolUse hook uses to refuse the tool call.
const exitDeny = 2

// preToolUse is the part of the client's payload this needs. Everything else is ignored
// rather than modelled: a hook that fails to parse fields it does not use is a hook that
// breaks on the next release of the client.
type preToolUse struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Skill string `json:"skill"`
	} `json:"tool_input"`
}

// runHookPreSkill checks one managed skill immediately before its instructions are loaded.
//
// The session-start reconciler covers what changed while nobody was looking; this covers the
// gap it cannot — a managed skill edited *during* a session, after that reconciler already
// ran. Between "these bytes changed" and "these bytes are about to be followed with your
// credentials" is the whole window, and PreToolUse is the only event here that can refuse.
//
// It restores rather than merely refusing, where restoring is possible. Denying a skill the
// organisation publishes would block work over a difference the tool can simply correct, and
// the agent then loads the published bytes instead of the edited ones. Refusal is kept for
// the cases where there are no correct bytes to hand over: a revoked skill, or a catalog
// this machine cannot currently verify.
func runHookPreSkill(args []string) int {
	flags := flag.NewFlagSet("hook pre-skill", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl hook pre-skill [flags]\n\n"+
			"Reads a PreToolUse payload on stdin. If the named skill is centrally managed\n"+
			"and has been changed here, it is restored before it loads; if it is revoked or\n"+
			"cannot be verified, the call is refused. Skills no catalog claims are allowed\n"+
			"without a word.\n\n"+
			"Exit codes: %d allow, %d refuse.\n\nFlags:\n", exitClean, exitDeny)
		flags.PrintDefaults()
	}

	into := flags.String("into", "", "skills directory to manage (default ~/.agents/skills)")
	permissive := flags.Bool("permissive", false,
		"warn instead of refusing when a managed skill cannot be verified")

	if err := parseArgs(flags, args); err != nil {
		return exitClean
	}

	name := skillFromPayload(os.Stdin)
	if name == "" {
		return exitClean
	}

	subscriptions, err := loadSubscriptions()
	if err != nil || len(subscriptions) == 0 {
		return exitClean // this machine is not centrally managed
	}
	installRoot, err := installRoot(*into)
	if err != nil {
		return exitClean
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return exitClean
	}

	now := time.Now().UTC()
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, now)
		if err != nil {
			// Only refuse over a catalog that actually claims this skill. A machine whose
			// unrelated catalog expired must not lose access to every other skill it has.
			if claimsName(subscription, name) {
				fmt.Fprintf(os.Stderr, "skillctl: %q is managed by %s, which this machine "+
					"cannot verify right now, so it was not allowed to load: %v\n"+
					"  fix with: skillctl sync\n", name, subscription.Name, err)
				if *permissive {
					return exitClean
				}
				return exitDeny
			}
			continue
		}

		managed, published := snapshot.Publishes(name)
		if !published {
			continue
		}
		return enforce(subscription, snapshot, managed, installRoot, now, *permissive)
	}
	return exitClean // no catalog claims this skill
}

// enforce is the decision for a skill that is definitely managed.
func enforce(
	subscription Subscription, snapshot *catalog.Snapshot, managed catalog.Managed,
	installRoot string, now time.Time, permissive bool,
) int {
	directory := filepath.Join(installRoot, managed.Name)

	if entry, revoked := snapshot.IsRevoked(managed.Digest); revoked {
		fmt.Fprintf(os.Stderr, "skillctl: %q has been revoked by %s and was not loaded\n",
			managed.Name, subscription.Name)
		if entry.Reason != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", entry.Reason)
		}
		return exitDeny
	}

	if built, err := archive.Build(directory, archive.Limits{}); err == nil &&
		built.Digest == managed.Digest {
		return exitClean // the published bytes, unchanged
	}

	// Changed, missing or unreadable. Reconciling this one skill hands the agent the bytes
	// the organisation published instead of whatever is there now.
	state, err := fleet.LoadState(statePath(subscription.Name))
	if err != nil {
		return refuse(managed.Name, err, permissive)
	}
	single := *snapshot
	single.Skills = []catalog.Managed{managed}

	changes, err := fleet.Reconcile(&single, state, fleet.Options{
		SourceRoot:     source.Path(catalogRoot(), subscription.Name),
		InstallRoot:    installRoot,
		QuarantineRoot: quarantineRoot(),
		Now:            now,
	})
	if err != nil {
		return refuse(managed.Name, err, permissive)
	}
	if err := state.Save(statePath(subscription.Name)); err != nil {
		return refuse(managed.Name, err, permissive)
	}

	for _, change := range changes {
		if change.Name != managed.Name {
			continue
		}
		if change.Action == fleet.ActionFailed {
			return refuse(managed.Name, fmt.Errorf("%s", change.Reason), permissive)
		}
		if change.Action == fleet.ActionRolledBack {
			fmt.Fprintf(os.Stderr, "skillctl: %q had been changed on this machine and was "+
				"restored to what %s publishes before it loaded\n",
				managed.Name, subscription.Name)
			if change.Quarantine != "" {
				fmt.Fprintf(os.Stderr, "  what was there: %s\n", change.Quarantine)
			}
		}
	}
	return exitClean
}

func refuse(name string, err error, permissive bool) int {
	fmt.Fprintf(os.Stderr, "skillctl: %q is centrally managed and could not be put back, "+
		"so it was not loaded: %v\n", name, err)
	if permissive {
		return exitClean
	}
	return exitDeny
}

// claimsName reports whether a catalog names this skill, read without verification.
//
// It is used only to decide whether an unverifiable catalog is relevant to the skill being
// loaded, never to decide that the skill is fine. Reading an unverified index for that
// narrow purpose is safe in a way reading it for a verdict would not be: the worst an
// attacker achieves by editing it is causing their own skill to be refused.
func claimsName(subscription Subscription, name string) bool {
	path := filepath.Join(source.Path(catalogRoot(), subscription.Name), CatalogFileName)
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		return false
	}
	payload, err := envelope.DecodedPayload()
	if err != nil {
		return false
	}
	var snapshot catalog.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return false
	}
	_, claimed := snapshot.Publishes(name)
	return claimed
}

// skillFromPayload extracts the skill name a client is about to load.
func skillFromPayload(reader io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		return ""
	}
	var payload preToolUse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	name := payload.ToolInput.Skill
	// Plugin skills arrive as "plugin:skill"; the bare name is what SKILL.md declares and
	// what a catalog publishes.
	if _, suffix, found := strings.Cut(name, ":"); found && suffix != "" {
		return suffix
	}
	return name
}
