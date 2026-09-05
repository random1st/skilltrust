package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tools are the actions. They are thin on purpose: each one is a skillctl invocation with a
// schema, a description that says what it changes, and an annotation saying whether it is
// safe to call while thinking.
//
// Two rules hold across all of them. No tool returns a private key or a token — the one
// place a secret would appear is the signing key, and it is never read. And no tool hides a
// non-zero exit: skillctl says things with exit codes, so the code is reported rather than
// translated into a failure.
func (s *server) addTools(m *mcp.Server) {
	safe := &mcp.ToolAnnotations{ReadOnlyHint: true}
	writes := &mcp.ToolAnnotations{IdempotentHint: true}
	mcp.AddTool(m, &mcp.Tool{
		Name: "skilltrust_publish", Title: "Publish or renew this repository's skills",
		Description: "Starts or resumes publishing with the original local signer. Handles browser team approval, prepares the catalog and workflow and returns a review ID. After the user approves that exact review, submit=true and approve=<review ID> commit those two files, push the branch and verify both publisher and notary signatures on the exact hosted catalog. renew=true only extends unchanged approvals. Never returns keys, key paths or tokens.",
		Annotations: writes,
	}, s.publish)
	mcp.AddTool(m, &mcp.Tool{
		Name: "skilltrust_status", Title: "Check connection, skills and report delivery",
		Description: "Shows public machine state and one next action with its responsible person. With refresh=true, checks installed skills and sends a signed report; never installs or restores skills. Without refresh, describes the last recorded check, not a new verification.",
		Annotations: writes,
	}, s.status)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_init",
		Title:       "Create this machine's signing key",
		Description: "Creates the signing key and pinned-key set under the SkillTrust home, if they are not there. Returns the public half. Safe to call twice; an existing key is never replaced, because replacing it would silently unpin this machine everywhere it is trusted.",
		Annotations: writes,
	}, s.init)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_connect",
		Title:       "Connect this machine to Axela",
		Description: "Starts or resumes the browser-approved Axela connection with the real skillctl connect flow. It returns only safe status fields such as the machine key fingerprint, approval URL, dashboard URL, and next steps; it never returns the private key or the reporting token. The MCP tool keeps browser approval explicit by printing the approval URL instead of opening a browser tab itself.",
		Annotations: writes,
	}, s.connect)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_trust_key",
		Title:       "Pin a public key",
		Description: "Pins a PEM public key under a label, so signatures made with it are accepted. Pin before subscribing: a catalog is only as trustworthy as the key that was pinned for it beforehand.",
		Annotations: writes,
	}, s.trustKey)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_subscribe",
		Title:       "Follow a signed catalog",
		Description: "Follows an organisation's catalog, pinning the keys allowed to sign it. Set threshold to the number of keys given when there is more than one — the default of 1 accepts any single one of them, which is not what pinning two keys is usually for.",
		Annotations: writes,
	}, s.subscribe)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_check",
		Title:       "Report what differs, changing nothing",
		Description: "Verifies every followed catalog and reports which installed skills differ from what was signed. Writes nothing. Use this before skilltrust_sync, and to answer questions about the machine's state.",
		Annotations: safe,
	}, s.check)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_sync",
		Title:       "Put back what was changed",
		Description: "Fetches, verifies, and restores skills that differ from the signed version, keeping the copy that was there. Exit code 1 means something was changed, not that it failed. This modifies files: prefer skilltrust_check unless restoring is what was asked for.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)},
	}, s.sync)

	mcp.AddTool(m, &mcp.Tool{
		Name:  "skilltrust_install_hook",
		Title: "Check at the start of every session",
		Description: "Installs the SessionStart hook into the client's settings, so the check " +
			"runs without anyone remembering: it puts back any centrally managed plugin changed " +
			"here and reports skills that no longer match their approval. It does not install " +
			"the per-skill PreToolUse check — that one ships with the SkillTrust plugin, because " +
			"a hook firing on every skill invocation should arrive with something installed on " +
			"purpose. Call with apply=false first to show the change; nothing is written until " +
			"apply=true, and a backup is kept.",
		Annotations: writes,
	}, s.installHook)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_lint",
		Title:       "Inventory skills and report risk indicators",
		Description: "Scans a tree for skills and reports specification deviations and content risk indicators. Entirely offline, changes nothing. This describes what a skill looks like — it is not a statement that it is safe.",
		Annotations: safe,
	}, s.lint)

	mcp.AddTool(m, &mcp.Tool{
		Name:  "skilltrust_verify_skills",
		Title: "Check skills against the approvals this machine holds",
		Description: "Recomputes every skill's digest and checks it against the signed approvals in " +
			"this machine's attestation store, and against any attestation beside a skill. Writes nothing. " +
			"Use this for skills that came from anywhere other than a signed marketplace — a repository, " +
			"a copy, a colleague — which is most of them on Cursor and Antigravity, where nothing is " +
			"installed from a marketplace at all. Unlike skilltrust_lint this is a statement about bytes, " +
			"not about what a skill looks like. Exit code 1 means a skill no longer matches its approval.",
		Annotations: safe,
	}, s.verifySkills)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_sign_marketplace",
		Title:       "Sign the skills a repository publishes",
		Description: "Signs the plugins a Claude Code marketplace owns, writing the signed index into the repository. Run in the repository that publishes the skills, with this machine's key.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: false},
	}, s.signMarketplace)

	mcp.AddTool(m, &mcp.Tool{
		Name:  "skilltrust_prepare_publish_workflow",
		Title: "Prepare the GitHub Actions publish workflow",
		Description: "Writes the GitHub Actions workflow that submits an already-signed " +
			"catalog to a SkillTrust notary with the job's OIDC token. This changes files " +
			"locally, but it does not publish anything: the first real publish is the first " +
			"accepted workflow run that uploads a signed non-empty catalog.",
		Annotations: writes,
	}, s.preparePublishWorkflow)
}

type emptyInput struct{}

type initInput struct {
	As string `json:"as,omitempty" jsonschema:"the identity recorded on approvals made from this machine; defaults to the git email"`
}

func (s *server) init(ctx context.Context, _ *mcp.CallToolRequest, in initInput) (*mcp.CallToolResult, result, error) {
	args := []string{"init"}
	if in.As != "" {
		args = append(args, "-as", in.As)
	}
	return s.call(ctx, "", args...)
}

type connectInput struct {
	ServiceURL  string `json:"service_url,omitempty" jsonschema:"Axela base URL. Pass it on the first run; omit it when resuming a pending or already connected machine."`
	Machine     string `json:"machine,omitempty" jsonschema:"short name for this computer; defaults to the hostname"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"how many seconds to wait for browser approval before returning. Defaults to 0 for an immediate browser handoff; max 60"`
}

func (s *server) connect(ctx context.Context, _ *mcp.CallToolRequest, in connectInput) (*mcp.CallToolResult, result, error) {
	if in.WaitSeconds < 0 || in.WaitSeconds > 60 {
		return nil, result{}, fmt.Errorf("wait_seconds must be between 0 and 60")
	}
	args := []string{"connect", "-no-browser", "-wait", (time.Duration(in.WaitSeconds) * time.Second).String()}
	if in.Machine != "" {
		args = append(args, "-machine", in.Machine)
	}
	if in.ServiceURL != "" {
		args = append(args, in.ServiceURL)
	}
	reply, result, err := s.call(ctx, "", args...)
	if err == nil {
		if status, statusErr := s.run.run(ctx, "", "status", "--json"); statusErr == nil && status.State != nil {
			result.State = status.State
		}
	}
	return reply, result, err
}

type statusInput struct {
	Refresh bool `json:"refresh,omitempty" jsonschema:"run a current check and deliver its report; otherwise read the last recorded state"`
}

type publishInput struct {
	Directory    string `json:"directory" jsonschema:"local Git repository containing the marketplace"`
	Organisation string `json:"organisation,omitempty" jsonschema:"team name on the first run; remembered for later runs"`
	ServiceURL   string `json:"service_url,omitempty" jsonschema:"Axela URL on first run; defaults to https://axela.app"`
	Branch       string `json:"branch,omitempty" jsonschema:"publishing branch; defaults to the checked-out branch"`
	Renew        bool   `json:"renew,omitempty" jsonschema:"extend unchanged approvals with the original signing key"`
	Submit       bool   `json:"submit,omitempty" jsonschema:"commit and push only after the user approves the returned review"`
	Approve      string `json:"approve,omitempty" jsonschema:"exact review ID approved by the user; required for submit"`
	Status       bool   `json:"status,omitempty" jsonschema:"verify the saved hosted revision without preparing or pushing"`
	WaitSeconds  int    `json:"wait_seconds,omitempty" jsonschema:"wait for publication, from 0 to 60 seconds"`
}

func (s *server) publish(ctx context.Context, _ *mcp.CallToolRequest, in publishInput) (*mcp.CallToolResult, result, error) {
	if strings.TrimSpace(in.Directory) == "" {
		return nil, result{}, fmt.Errorf("directory is required")
	}
	if in.WaitSeconds < 0 || in.WaitSeconds > 60 {
		return nil, result{}, fmt.Errorf("wait_seconds must be between 0 and 60")
	}
	args := []string{"publish", "--json", "--no-browser", "--wait", strconv.Itoa(in.WaitSeconds) + "s"}
	for _, option := range [][2]string{{"--org", in.Organisation}, {"--notary", in.ServiceURL}, {"--branch", in.Branch}, {"--approve", in.Approve}} {
		if option[1] != "" {
			args = append(args, option[0], option[1])
		}
	}
	if in.Renew {
		args = append(args, "--renew")
	}
	if in.Submit {
		args = append(args, "--submit")
	}
	if in.Status {
		args = append(args, "--status")
	}
	args = append(args, "--", in.Directory)
	return s.call(ctx, in.Directory, args...)
}

func (s *server) status(ctx context.Context, _ *mcp.CallToolRequest, in statusInput) (*mcp.CallToolResult, result, error) {
	args := []string{"status", "--json"}
	if in.Refresh {
		args = append(args, "--refresh")
	}
	return s.call(ctx, "", args...)
}

type trustKeyInput struct {
	PublicKey string `json:"public_key" jsonschema:"the PEM public key to pin, beginning -----BEGIN PUBLIC KEY-----"`
	Label     string `json:"label" jsonschema:"the name to pin it under; use the organisation or machine it belongs to"`
}

func (s *server) trustKey(ctx context.Context, _ *mcp.CallToolRequest, in trustKeyInput) (*mcp.CallToolResult, result, error) {
	if strings.TrimSpace(in.Label) == "" {
		return nil, result{}, fmt.Errorf("a label is required: an unlabelled pin cannot be removed later without guessing which key it is")
	}
	path, cleanup, err := writeTemp(in.Label+".pub", in.PublicKey)
	if err != nil {
		return nil, result{}, err
	}
	defer cleanup()
	return s.call(ctx, "", "trust", "-label", in.Label, path)
}

type subscribeInput struct {
	Repository string   `json:"repository" jsonschema:"the git URL of the repository holding the skills"`
	PublicKeys []string `json:"public_keys" jsonschema:"the PEM public keys of the publishers allowed to sign this catalog"`
	NotaryKeys []string `json:"notary_keys,omitempty" jsonschema:"the PEM public keys of the notary countersigning this catalog; several keys mid-rotation belong to one signer and count once, so pass them here rather than in public_keys"`
	CatalogURL string   `json:"catalog_url,omitempty" jsonschema:"HTTPS URL of the signed index, when a notary serves it instead of the repository"`
	Name       string   `json:"name,omitempty" jsonschema:"short name for this catalog; defaults to the repository name"`
	Ref        string   `json:"ref,omitempty" jsonschema:"branch or tag to follow; defaults to the repository HEAD"`
	Threshold  int      `json:"threshold,omitempty" jsonschema:"how many distinct signers must have signed; defaults to every signer given, which is what makes one stolen key insufficient"`
}

func (s *server) subscribe(ctx context.Context, _ *mcp.CallToolRequest, in subscribeInput) (*mcp.CallToolResult, result, error) {
	if in.Repository == "" {
		return nil, result{}, fmt.Errorf("a repository is required")
	}
	if len(in.PublicKeys)+len(in.NotaryKeys) == 0 {
		return nil, result{}, fmt.Errorf("at least one public key is required: a subscription with no pinned key would accept any signature")
	}

	args := []string{"subscribe"}
	for index, key := range in.PublicKeys {
		path, cleanup, err := writeTemp(fmt.Sprintf("signer-%d.pub", index), key)
		if err != nil {
			return nil, result{}, err
		}
		defer cleanup()
		args = append(args, "-key", path)
	}
	// A notary's keys go in as one signer. Several exist only while it rotates, and
	// counted separately they would satisfy a threshold of two between themselves — the
	// exact "a compromised notary publishes nothing alone" property the second key is
	// pinned to buy.
	for index, key := range in.NotaryKeys {
		path, cleanup, err := writeTemp(fmt.Sprintf("notary-%d.pub", index), key)
		if err != nil {
			return nil, result{}, err
		}
		defer cleanup()
		args = append(args, "-notary-key", path)
	}

	// Defaulting to every signer given, rather than to one. Someone who pins a publisher
	// and a notary is asking for both signatures; accepting one of them is the failure the
	// second key was pinned to prevent, and it fails silently — everything verifies, forever.
	threshold := in.Threshold
	if threshold < 1 {
		threshold = len(in.PublicKeys)
		if len(in.NotaryKeys) > 0 {
			threshold++
		}
	}
	args = append(args, "-threshold", strconv.Itoa(threshold))

	if in.CatalogURL != "" {
		args = append(args, "-catalog", in.CatalogURL)
	}
	if in.Name != "" {
		args = append(args, "-name", in.Name)
	}
	if in.Ref != "" {
		args = append(args, "-ref", in.Ref)
	}
	args = append(args, in.Repository)
	return s.call(ctx, "", args...)
}

type checkInput struct {
	Offline bool `json:"offline,omitempty" jsonschema:"check against the catalogs already fetched instead of fetching"`
}

func (s *server) check(ctx context.Context, _ *mcp.CallToolRequest, in checkInput) (*mcp.CallToolResult, result, error) {
	args := []string{"sync", "-report-only"}
	if in.Offline {
		args = append(args, "-offline")
	}
	return s.call(ctx, "", args...)
}

type syncInput struct {
	Offline bool `json:"offline,omitempty" jsonschema:"reconcile against the catalogs already fetched instead of fetching"`
}

func (s *server) sync(ctx context.Context, _ *mcp.CallToolRequest, in syncInput) (*mcp.CallToolResult, result, error) {
	args := []string{"sync"}
	if in.Offline {
		args = append(args, "-offline")
	}
	return s.call(ctx, "", args...)
}

type installHookInput struct {
	Apply bool `json:"apply" jsonschema:"write the change; false prints what would be written and touches nothing"`
}

func (s *server) installHook(ctx context.Context, _ *mcp.CallToolRequest, in installHookInput) (*mcp.CallToolResult, result, error) {
	args := []string{"hook", "install"}
	if in.Apply {
		args = append(args, "-apply")
	}
	return s.call(ctx, "", args...)
}

type lintInput struct {
	Path        string `json:"path,omitempty" jsonschema:"directory to scan; defaults to every conventional skills directory"`
	Format      string `json:"format,omitempty" jsonschema:"text, json or sarif; defaults to json so the findings can be read as data"`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"only list findings at this level or above: high, medium, low, info. Defaults to medium, which keeps the reply readable; the counts are always of everything found. Pass info for the full list"`
}

func (s *server) lint(ctx context.Context, _ *mcp.CallToolRequest, in lintInput) (*mcp.CallToolResult, result, error) {
	format := in.Format
	if format == "" {
		format = "json"
	}
	// never, so a tree with findings is reported rather than returned as a failed tool: the
	// findings are the answer.
	// A real machine is a hundred skills and a couple of hundred findings, most of them the
	// two shapes every skill carrying a script has. Returned in full that is tens of
	// kilobytes into the context of whoever asked, which is a cost the caller pays without
	// being offered the choice — so the default is medium and the summary still counts
	// everything. This differs from the CLI default deliberately: a terminal scrolls and a
	// context window does not.
	minSeverity := in.MinSeverity
	if minSeverity == "" {
		minSeverity = "medium"
	}
	args := []string{"lint", "-format", format, "-fail-on", "never", "-min-severity", minSeverity}
	if in.Path != "" {
		args = append(args, in.Path)
	}
	return s.call(ctx, "", args...)
}

// verifySkills answers the question the marketplace tools cannot: whether skills that
// nobody published still match what somebody approved.
//
// It was missing while the CLI could already do it, which left the MCP surface promising in
// its own instructions that SkillTrust "proves who published a skill's bytes and that they
// have not changed" while offering an agent no way to ask that about three of the four
// clients it supports.
func (s *server) verifySkills(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, result, error) {
	return s.call(ctx, "", "attest", "verify")
}

type signMarketplaceInput struct {
	Directory string `json:"directory" jsonschema:"the repository holding the marketplace to sign"`
}

func (s *server) signMarketplace(ctx context.Context, _ *mcp.CallToolRequest, in signMarketplaceInput) (*mcp.CallToolResult, result, error) {
	if in.Directory == "" {
		return nil, result{}, fmt.Errorf("a directory is required: signing whatever the server's working directory happens to be is how the wrong tree gets signed")
	}
	return s.call(ctx, in.Directory, "marketplace", "sign", ".")
}

type preparePublishWorkflowInput struct {
	Directory    string `json:"directory" jsonschema:"the repository holding the marketplace and the workflow to write"`
	Organisation string `json:"organisation" jsonschema:"the hosted-notary organisation name already registered in the console"`
	Marketplace  string `json:"marketplace,omitempty" jsonschema:"marketplace name at the notary; defaults to the repository's .claude-plugin/marketplace.json name"`
	Branch       string `json:"branch,omitempty" jsonschema:"branch that should trigger publication; defaults to main"`
	Workflow     string `json:"workflow,omitempty" jsonschema:"workflow file to write; defaults to .github/workflows/notarize.yml"`
	NotaryURL    string `json:"notary_url,omitempty" jsonschema:"SkillTrust notary base URL; defaults to https://notary.axela.app"`
}

func (s *server) preparePublishWorkflow(ctx context.Context, _ *mcp.CallToolRequest, in preparePublishWorkflowInput) (*mcp.CallToolResult, result, error) {
	if in.Directory == "" {
		return nil, result{}, fmt.Errorf("a directory is required: the workflow must be written into the repository it will publish from")
	}
	if strings.TrimSpace(in.Organisation) == "" {
		return nil, result{}, fmt.Errorf("an organisation is required")
	}
	args := []string{"marketplace", "prepare-notary", "-org", in.Organisation}
	if in.Marketplace != "" {
		args = append(args, "-marketplace", in.Marketplace)
	}
	if in.Branch != "" {
		args = append(args, "-branch", in.Branch)
	}
	if in.Workflow != "" {
		args = append(args, "-workflow", in.Workflow)
	}
	if in.NotaryURL != "" {
		args = append(args, "-notary", in.NotaryURL)
	}
	args = append(args, ".")
	return s.call(ctx, in.Directory, args...)
}

// call runs skillctl and shapes the result. The output is returned as the content an agent
// reads, and the exit code beside it, because the two mean different things and collapsing
// them loses the one that says whether anything changed.
func (s *server) call(ctx context.Context, dir string, args ...string) (*mcp.CallToolResult, result, error) {
	out, err := s.run.run(ctx, dir, args...)
	if err != nil {
		return nil, result{}, err
	}
	body := out.Output
	if body == "" {
		body = fmt.Sprintf("%s finished with exit code %d and said nothing.", out.Command, out.ExitCode)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: body}},
	}, out, nil
}

func boolPtr(value bool) *bool { return &value }
