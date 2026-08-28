package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
		Name:        "skilltrust_init",
		Title:       "Create this machine's signing key",
		Description: "Creates the signing key and pinned-key set under the SkillTrust home, if they are not there. Returns the public half. Safe to call twice; an existing key is never replaced, because replacing it would silently unpin this machine everywhere it is trusted.",
		Annotations: writes,
	}, s.init)

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
		Name:        "skilltrust_install_hook",
		Title:       "Check at the start of every session",
		Description: "Installs the SessionStart and PreToolUse hooks into the client's settings, so verification happens without anyone remembering. Call with apply=false first to show the change; nothing is written until apply=true, and a backup is kept.",
		Annotations: writes,
	}, s.installHook)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_lint",
		Title:       "Inventory skills and report risk indicators",
		Description: "Scans a tree for skills and reports specification deviations and content risk indicators. Entirely offline, changes nothing. This describes what a skill looks like — it is not a statement that it is safe.",
		Annotations: safe,
	}, s.lint)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "skilltrust_sign_marketplace",
		Title:       "Sign the skills a repository publishes",
		Description: "Signs the plugins a Claude Code marketplace owns, writing the signed index into the repository. Run in the repository that publishes the skills, with this machine's key.",
		Annotations: writes,
	}, s.signMarketplace)
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
	PublicKeys []string `json:"public_keys" jsonschema:"the PEM public keys allowed to sign this catalog; for a hosted notary this is the publisher's key and the notary's"`
	CatalogURL string   `json:"catalog_url,omitempty" jsonschema:"HTTPS URL of the signed index, when a notary serves it instead of the repository"`
	Name       string   `json:"name,omitempty" jsonschema:"short name for this catalog; defaults to the repository name"`
	Ref        string   `json:"ref,omitempty" jsonschema:"branch or tag to follow; defaults to the repository HEAD"`
	Threshold  int      `json:"threshold,omitempty" jsonschema:"how many distinct pinned keys must have signed; defaults to the number of keys given"`
}

func (s *server) subscribe(ctx context.Context, _ *mcp.CallToolRequest, in subscribeInput) (*mcp.CallToolResult, result, error) {
	if in.Repository == "" {
		return nil, result{}, fmt.Errorf("a repository is required")
	}
	if len(in.PublicKeys) == 0 {
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

	// Defaulting to the number of keys given, rather than to skillctl's 1. Someone who pins
	// two keys is asking for two signatures; accepting one of them is the failure the second
	// key was pinned to prevent, and it fails silently — everything verifies, forever.
	threshold := in.Threshold
	if threshold < 1 {
		threshold = len(in.PublicKeys)
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
	Path   string `json:"path,omitempty" jsonschema:"directory to scan; defaults to the conventional skills directories"`
	Format string `json:"format,omitempty" jsonschema:"text, json or sarif; defaults to json so the findings can be read as data"`
}

func (s *server) lint(ctx context.Context, _ *mcp.CallToolRequest, in lintInput) (*mcp.CallToolResult, result, error) {
	format := in.Format
	if format == "" {
		format = "json"
	}
	// never, so a tree with findings is reported rather than returned as a failed tool: the
	// findings are the answer.
	args := []string{"lint", "-format", format, "-fail-on", "never"}
	if in.Path != "" {
		args = append(args, in.Path)
	}
	return s.call(ctx, "", args...)
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
