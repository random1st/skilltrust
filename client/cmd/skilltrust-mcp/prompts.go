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
		Title:       "Follow an organisation's signed skills on this machine",
		Description: "The consumer side, in order: key, pins, subscription, first check, hook.",
		Arguments: []*mcp.PromptArgument{
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

	return prompt("Setting up SkillTrust on this machine", fmt.Sprintf(`Set this machine up to follow signed skills%s.

Read skilltrust://state first. It says what is already done, and its next_step field names
the one thing to do now. Setting up a machine that is already set up is the common failure
here, because every step succeeds a second time.

Then, in this order, and not another:

1. skilltrust_init, unless state says a signing key exists. This key signs the events this
   machine files; its public half is what an administrator pins to believe them.

2. skilltrust_trust_key for each key you were given, with a label naming who it belongs to.
   Pin before subscribing. The keys must come from somewhere you already trust — a key taken
   from the catalog it is meant to verify makes the signature a formality, because a catalog
   that can supply its own key can replace itself.

   With a hosted notary there are two keys: the publisher's and the notary's. Both are
   pinned, and the point of the pair is that neither alone is enough.

3. skilltrust_subscribe with every key you pinned — the publisher's in public_keys, the
   notary's in notary_keys. The split matters: a notary that is rotating has two keys, and
   passed as ordinary public keys they would count as two separate signers, so the notary's
   own two signatures would satisfy a threshold of two with no publisher at all. Leave
   threshold unset; this server defaults it to every signer you passed. Setting it to 1
   with two signers pinned means either alone publishes — the situation the second key was
   pinned to prevent, and nothing will ever report it as wrong.

4. skilltrust_check. It writes nothing. Read what it says before restoring anything: a
   difference is not necessarily an attack, and the copy on disk may be work someone has
   not committed.

5. skilltrust_install_hook with apply=false, show the change, then apply=true. Without this,
   verification happens when someone remembers, which is not a security property.

Say what you did and what is now pinned. Do not report the machine as protected if step 5
was not applied — checking on demand and checking every session are different claims.`, target))
}

func (s *server) publishRepository(_ context.Context, request *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	directory := request.Params.Arguments["directory"]
	if directory == "" {
		directory = "the repository you are working in"
	}

	return prompt("Publishing a signed catalog", fmt.Sprintf(`Publish the skills in %s as a signed catalog.

Read skilltrust://state and skilltrust://guide/setup first.

1. skilltrust_init if there is no key yet. The private half never leaves this machine, and
   nothing you do later should copy it anywhere, including into CI.

2. Read skilltrust://identity and give the human that PEM public key. Registering it is a
   step you cannot do: it happens in a browser, behind a sign-in, and the registration hands
   back three tokens shown exactly once.

   Tell them plainly: open the console, register the organisation, paste that public key,
   and keep the tokens somewhere they will still exist tomorrow. Ask them to put the publish
   token in the environment rather than pasting it to you — a token in this conversation is a
   token in a transcript, and a lost one is rotated, not recovered.

3. skilltrust_sign_marketplace on the directory. This signs the plugins the marketplace owns
   and writes the signed index into the repository. Commit it.

4. Publishing the index is an HTTPS PUT with the publish token, or a GitHub Actions job that
   mints its own identity and stores no secret at all. Prefer the second and say why: there
   is nothing in CI to leak.

The signature is always made here, by the key registered. Nothing you publish later can be
accepted if this key did not sign it, which is what makes step 4 safe to automate.`, directory))
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
