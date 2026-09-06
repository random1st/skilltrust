package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Prompts are the part an agent cannot infer from tool schemas: the order, and the reasons
// the order matters. Every tool here succeeds when called in the wrong sequence — pinning
// after subscribing, subscribing without a threshold, syncing before checking — and the
// result verifies cleanly while protecting nobody. That failure is invisible, so it is
// written down rather than left to be worked out.
func (s *server) addPrompts(m *mcp.Server) {
	m.AddPrompt(&mcp.Prompt{
		Name:        "set_up_this_machine",
		Title:       "Follow signed skills or join your Axela team",
		Description: "Account-free setup for a publisher's catalog, or browser-approved connection when a team service is requested.",
		Arguments: []*mcp.PromptArgument{
			{Name: "service_url", Description: "Axela base URL when the user wants to join a team"},
			{Name: "catalog_url", Description: "HTTPS URL of the signed catalog, if a notary serves it"},
			{Name: "repository", Description: "git URL of the repository holding the skills"},
		},
	}, s.setUpMachine)

	m.AddPrompt(&mcp.Prompt{
		Name:        "publish_this_repository",
		Title:       "Publish this repository's skills as a signed catalog",
		Description: "The publisher side, including the one step an agent cannot do alone.",
		Arguments: []*mcp.PromptArgument{
			{Name: "directory", Description: "path to the repository holding the skills"},
		},
	}, s.publishRepository)

	m.AddPrompt(&mcp.Prompt{
		Name:        "investigate_change",
		Title:       "Work out why a skill was restored or refused",
		Description: "What to read, in what order, when verification refused something.",
		Arguments: []*mcp.PromptArgument{
			{Name: "skill", Description: "name of the skill concerned, if known"},
		},
	}, s.investigateChange)
}

func (s *server) setUpMachine(_ context.Context, request *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	args := request.Params.Arguments
	target := describeTarget(args["repository"], args["catalog_url"])
	service := strings.TrimSpace(args["service_url"])
	connectArgs := "with no arguments if this machine is already pending or connected"
	if service != "" {
		connectArgs = "with service_url set to " + service
	}

	local := `Follow a publisher without an account (including a local or self-hosted notary):

Keep the target client consistent: for Codex pass agent=codex to skilltrust_check and
skilltrust_sync, and client=codex to skilltrust_install_hook. These tools default to Claude.

1. Obtain the publisher's public key and repository from a source the user trusts.
   For a notary, also obtain its public key and catalog URL. Do not invent keys or learn
   the verification key from the signed catalog itself.

2. Use skilltrust_subscribe with the publisher keys in public_keys and the notary keys in
   notary_keys. Leave threshold unset to require every distinct signer. Subscription
   creates the local machine key if needed; do not replace any existing key.

3. Run skilltrust_check before installing or restoring anything. An expired, revoked or
   unverifiable catalog stops this path. An expired catalog needs renewal by its publisher
   with the original signing key; signing in or lowering the threshold does not repair it.

4. If no approved plugin is installed, use the client's native marketplace and plugin
   installation commands for the chosen publisher. Run skilltrust_check again afterwards.
   A successful subscription or zero checked plugins is not successful protection.
   Review changed files with the user before using skilltrust_sync to restore them.

5. After a nonempty check succeeds, call skilltrust_install_hook with apply=false, show the
   change, then apply=true once authorized. Finally use skilltrust_status with refresh=true.
   Report the checked skills and the hook state. Local verification needs no cloud receipt.`

	hosted := fmt.Sprintf(`Join an existing Axela team, when requested by the user:

1. Use skilltrust_connect %s. It creates or reuses the machine key, returns browser approval
   and configures catalogs and reporting after approval. It never returns a private key or
   reporting token.

2. If pending, use the approval URL in a browser already signed into Axela, confirm there,
   and run skilltrust_connect again. Resume a saved pending connection rather than creating
   another one. If no team is available, the account-free path is still available; do not
   create a publisher organisation just to follow someone else's skills.

3. Do not report this machine as protected or fully connected until status is connected:
   this requires a nonempty current check and the matching cloud receipt.`, connectArgs)

	first, second := local, hosted
	if service != "" {
		first, second = hosted, local
	}
	return prompt("Setting up SkillTrust on this machine", fmt.Sprintf(`Set this machine up to follow signed skills%s.

Read skilltrust://state first and follow its next_step for existing setup. Preserve saved
team connection records. A pending approval does not prevent choosing local subscriptions
without a team. A team connection is only needed when the user requests that service.

%s

%s

Say which route was used and what was actually checked. An unapplied hook, an empty check or
an unusable catalog is unfinished setup.`, target, first, second))
}

func (s *server) publishRepository(_ context.Context, request *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	directory := request.Params.Arguments["directory"]
	if directory == "" {
		directory = "the repository you are working in"
	}

	return prompt("Publishing a signed catalog", fmt.Sprintf(`Publish the skills in %s as a signed catalog.

Read skilltrust://state and skilltrust://guide/setup first.

1. Call skilltrust_publish with directory and the team name. It remembers setup and the
   original signer. If it returns approval_pending, show the browser link. The owner signs
   in and confirms the team and repository; no copying keys or recovery tokens is needed.
   Call the same tool again after consent to continue.

2. If source changes need a commit, review them through the repository's normal Git workflow
   first. The publishing tool commits only its catalog and workflow.

3. When status is prepared, show the files, covered skills, any coverage limitations and
   the diff. Preparing the workflow is not a publish. Get approval of this concrete revision
   unless the user has already authorized these exact changes.

4. After approval, call skilltrust_publish with submit=true and approve set to that exact
   review_id. It commits and pushes the reviewed files through GitHub Actions OIDC.
   If submission fails, repeat with the same review_id; it reuses the saved commit.

5. Call skilltrust_publish with status=true to verify the outcome. Only status published
   means the exact hosted catalog verified against both publisher and notary signatures.
   A successful push or workflow preparation alone is not publication.

For renewal use the same tool with renew=true. It extends unchanged approvals with the
existing signing key and preserves revocations. Changed skill contents need a normal
publication review. Never replace the signing key to work around a missing original key.`, directory))
}

func (s *server) investigateChange(_ context.Context, request *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	skill := request.Params.Arguments["skill"]
	subject := "a skill"
	if skill != "" {
		subject = skill
	}

	return prompt("Investigating a refused or restored skill", fmt.Sprintf(`Work out why %s was restored or refused, and change nothing until you can say which it is.

1. skilltrust_check. It reports the difference without touching anything. Read the whole
   output, including what it says on stderr about which directories it looked at.

2. Read skilltrust://subscriptions. Establish which catalog claims this skill, which keys are
   pinned for it, and how many signatures are required. A skill no catalog claims is never
   touched or reported on — if it is not there, that is the answer.

3. Separate the three things that look alike:
   - the bytes on disk differ from what was signed (someone edited an installed skill),
   - the catalog is signed but by too few pinned keys (a threshold that is not met),
   - the catalog revoked this digest (the publisher withdrew it).
   Only the first is fixed by restoring. The third means the skill should not come back.

4. If the answer is that someone edited an installed skill, say so before restoring: their
   work is in that file, and skilltrust_sync keeps the copy it replaces but does not tell
   them where it went unless you do.

Report what you found and what you did not check. This tool proves who published bytes and
that they have not changed. It does not prove the skill is safe, and saying it does is worse
than saying nothing.`, subject))
}

func describeTarget(repository, catalogURL string) string {
	var parts []string
	if repository != "" {
		parts = append(parts, "from "+repository)
	}
	if catalogURL != "" {
		parts = append(parts, "with the catalog served at "+catalogURL)
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

func prompt(description, body string) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Description: description,
		Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: body},
		}},
	}, nil
}
