package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect stands the server up against an in-memory client, on a home the test owns.
//
// The fake skillctl is a script that echoes its arguments. Every tool here is a skillctl
// invocation, so what is worth pinning is the command each one builds — running the real
// binary would test skillctl, which has its own tests, and would leave keys on the machine
// running this one.
//
// Windows gets a .cmd, because a file named `skillctl` holding `#!/bin/sh` is not something
// Windows can execute: every one of these tests failed there with "executable file not
// found", which read as a broken tool rather than a test that assumed a POSIX shell.
func connect(t *testing.T) (*mcp.ClientSession, string) {
	t.Helper()

	home := t.TempDir()
	name, script := "skillctl", "#!/bin/sh\necho \"ARGS $@\"\n"
	if runtime.GOOS == "windows" {
		name, script = "skillctl.cmd", "@echo off\r\necho ARGS %*\r\n"
	}
	fake := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	s := &server{run: runner{binary: fake, home: home}, home: home}
	m := mcp.NewServer(&mcp.Implementation{Name: "skilltrust", Version: "test"}, nil)
	s.addResources(m)
	s.addPrompts(m)
	s.addTools(m)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := m.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverSession.Close() })

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).
		Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, home
}

func callText(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: name, Arguments: args,
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var body strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			body.WriteString(text.Text)
		}
	}
	if result.IsError {
		t.Fatalf("%s reported an error: %s", name, body.String())
	}
	return body.String()
}

// The threshold default is the whole reason this server exists rather than a page of
// instructions. skillctl defaults it to 1, so two pinned keys accept either one alone —
// everything verifies, forever, and nothing reports it. Two keys must mean two signatures
// unless the caller says otherwise.
func TestSubscribeDefaultsThresholdToTheNumberOfKeys(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_subscribe", map[string]any{
		"repository": "https://github.com/acme/skills",
		"public_keys": []string{"-----BEGIN PUBLIC KEY-----\naaa\n-----END PUBLIC KEY-----",
			"-----BEGIN PUBLIC KEY-----\nbbb\n-----END PUBLIC KEY-----"},
	})

	if !strings.Contains(body, "-threshold 2") {
		t.Fatalf("two pinned keys must require two signatures, got: %s", body)
	}
}

func TestSubscribeKeepsAnExplicitThreshold(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_subscribe", map[string]any{
		"repository": "https://github.com/acme/skills",
		"public_keys": []string{"-----BEGIN PUBLIC KEY-----\naaa\n-----END PUBLIC KEY-----",
			"-----BEGIN PUBLIC KEY-----\nbbb\n-----END PUBLIC KEY-----"},
		"threshold": 1,
	})

	if !strings.Contains(body, "-threshold 1") {
		t.Fatalf("an explicit threshold must survive, got: %s", body)
	}
}

// A subscription with nothing pinned would accept any signature, which is worse than no
// subscription because it looks like one.
func TestSubscribeRefusesWithNoKeys(t *testing.T) {
	session, _ := connect(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "skilltrust_subscribe",
		Arguments: map[string]any{"repository": "https://github.com/acme/skills"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("subscribing with no pinned key must be refused")
	}
}

// check must never write. It is the tool an agent reaches for while thinking, and the one
// difference between it and sync is the flag.
func TestCheckIsReportOnly(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_check", nil)
	if !strings.Contains(body, "-report-only") {
		t.Fatalf("check must not reconcile, got: %s", body)
	}
}

func TestConnectUsesTheBrowserHandoffFlowByDefault(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_connect", map[string]any{
		"service_url": "https://axela.example",
		"machine":     "work-laptop",
	})

	for _, expected := range []string{
		"connect",
		"-no-browser",
		"-wait 0s",
		"-machine work-laptop",
		"https://axela.example",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("connect command is missing %q: %s", expected, body)
		}
	}
}

func TestConnectCanWaitBrieflyWhenAsked(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_connect", map[string]any{
		"wait_seconds": 15,
	})
	if !strings.Contains(body, "-wait 15s") {
		t.Fatalf("connect must pass the bounded wait through, got: %s", body)
	}
}

// The hook is the difference between checking on demand and checking every session. Printing
// is the default so that an agent that calls it without thinking changes nothing.
func TestInstallHookDoesNotApplyUnlessAsked(t *testing.T) {
	session, _ := connect(t)

	printed := callText(t, session, "skilltrust_install_hook", map[string]any{"apply": false})
	if strings.Contains(printed, "-apply") {
		t.Fatalf("apply=false must not write, got: %s", printed)
	}
	applied := callText(t, session, "skilltrust_install_hook", map[string]any{"apply": true})
	if !strings.Contains(applied, "-apply") {
		t.Fatalf("apply=true must write, got: %s", applied)
	}
}

// lint's findings are the answer, not a failure. Letting it exit non-zero on findings would
// surface a tree full of information as a broken tool.
func TestLintDoesNotFailOnFindings(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_lint", nil)
	if !strings.Contains(body, "-fail-on never") {
		t.Fatalf("lint findings must not be reported as a tool failure, got: %s", body)
	}
}

// state is read before anything else, so it has to be readable on a machine where nothing
// exists yet — that is precisely when it is most needed.
func TestStateOnAnEmptyMachine(t *testing.T) {
	session, home := connect(t)

	result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{
		URI: "skilltrust://state",
	})
	if err != nil {
		t.Fatal(err)
	}
	var current state
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &current); err != nil {
		t.Fatal(err)
	}
	if current.Home != home {
		t.Fatalf("state describes %s, tools change %s", current.Home, home)
	}
	if current.HasSigningKey {
		t.Fatal("an empty home has no signing key")
	}
	if !strings.Contains(current.NextStep, "skilltrust_init") {
		t.Fatalf("the first step on an empty machine is init, got: %s", current.NextStep)
	}
}

// The private key has no URI. This asserts the absence, because the failure it prevents is
// one nobody notices until a key is in a transcript.
func TestNoResourceServesThePrivateKey(t *testing.T) {
	session, home := connect(t)

	if err := os.WriteFile(filepath.Join(home, "signer.key"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "signer.pub"), []byte("PUBLIC"), 0o644); err != nil {
		t.Fatal(err)
	}

	listed, err := session.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range listed.Resources {
		result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{
			URI: resource.URI,
		})
		if err != nil {
			t.Fatalf("%s: %v", resource.URI, err)
		}
		for _, contents := range result.Contents {
			if strings.Contains(contents.Text, "SECRET") {
				t.Fatalf("%s served the private key", resource.URI)
			}
		}
	}
}

// Every prompt has to render without arguments: a client lists them before anyone has
// decided what to fill in, and a prompt that only works fully specified is one an agent
// never reaches.
func TestPromptsRenderWithoutArguments(t *testing.T) {
	session, _ := connect(t)

	listed, err := session.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Prompts) == 0 {
		t.Fatal("no prompts offered")
	}
	for _, one := range listed.Prompts {
		result, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: one.Name})
		if err != nil {
			t.Fatalf("%s: %v", one.Name, err)
		}
		if len(result.Messages) == 0 {
			t.Fatalf("%s rendered nothing", one.Name)
		}
	}
}

func TestSetUpPromptLeadsWithHostedConnectAndBrowserApproval(t *testing.T) {
	session, _ := connect(t)

	result, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{
		Name: "set_up_this_machine",
		Arguments: map[string]string{
			"service_url": "https://axela.example",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Messages) == 0 {
		t.Fatal("setup prompt rendered nothing")
	}
	body := strings.Join(strings.Fields(result.Messages[0].Content.(*mcp.TextContent).Text), " ")
	for _, expected := range []string{
		"skilltrust_connect with service_url set to https://axela.example",
		"browser already signed into Axela",
		"run skilltrust_connect again",
		"Do not report this machine as protected or fully connected",
		"local or self-hosted notary",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("setup prompt is missing %q:\n%s", expected, body)
		}
	}
}

// Everything here is detection, and the guide is where an agent learns that. A guide that
// stopped saying so would be the most damaging edit in this package.
func TestSetupGuideKeepsTheHonestLimit(t *testing.T) {
	// Whitespace-normalised: the guide is hard-wrapped prose, and a test that pins where the
	// lines break fails on reflowing rather than on the claim going missing.
	flat := strings.Join(strings.Fields(setupGuide), " ")
	for _, claim := range []string{
		"does not prove the skill is safe",
		"This is detection, not enforcement",
		"normal consumer setup is `skilltrust_connect`",
		"rerun it after the browser step",
	} {
		if !strings.Contains(flat, claim) {
			t.Fatalf("the guide no longer says %q", claim)
		}
	}
}

// The MCP surface promised, in the server's own instructions, that SkillTrust "proves who
// published a skill's bytes and that they have not changed" — while offering an agent no
// way to ask that about a skill outside a signed marketplace. Three of the four clients
// supported install nothing from a marketplace, so for most of them the promise had no tool
// behind it. lint was the nearest thing and says of itself that it is not a safety verdict.
func TestSkillsOutsideAMarketplaceCanBeVerified(t *testing.T) {
	session, _ := connect(t)

	body := callText(t, session, "skilltrust_verify_skills", nil)
	if !strings.Contains(body, "attest") || !strings.Contains(body, "verify") {
		t.Fatalf("the tool must check skills against their approvals, got: %s", body)
	}
	// No directory argument: the whole machine, not whatever the agent happened to name.
	// A verification of one directory reported as a verification is how a clean answer gets
	// given about somewhere nobody asked about.
	if strings.Contains(body, "-attestation") {
		t.Fatalf("verification must cover every root, got: %s", body)
	}
}

// It writes nothing, which is what lets an agent reach for it while thinking. sync is the
// one that changes files and it is a different tool on purpose.
func TestVerifySkillsIsReadOnly(t *testing.T) {
	session, _ := connect(t)

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Name != "skilltrust_verify_skills" {
			continue
		}
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != true {
			t.Fatal("a tool an agent calls while thinking must be annotated read-only")
		}
		return
	}
	t.Fatal("skilltrust_verify_skills is not offered at all")
}

func TestPreparePublishWorkflowBuildsTheOIDCCommand(t *testing.T) {
	session, _ := connect(t)
	repository := t.TempDir()

	body := callText(t, session, "skilltrust_prepare_publish_workflow", map[string]any{
		"directory":    repository,
		"organisation": "acme",
		"marketplace":  "plugins",
		"branch":       "release",
		"workflow":     ".github/workflows/publish.yml",
		"notary_url":   "https://notary.example.com",
	})

	for _, expected := range []string{
		"marketplace",
		"prepare-notary",
		"-org acme",
		"-marketplace plugins",
		"-branch release",
		"-workflow .github/workflows/publish.yml",
		"-notary https://notary.example.com",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("prepare workflow command is missing %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "notary-token") {
		t.Fatalf("prepare workflow should not ask CI to hold a publish token: %s", body)
	}
}

func TestPublishPromptKeepsPreparationSeparateFromPublication(t *testing.T) {
	session, _ := connect(t)
	repository := t.TempDir()

	result, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{
		Name:      "publish_this_repository",
		Arguments: map[string]string{"directory": repository},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Messages) == 0 {
		t.Fatal("publish prompt rendered nothing")
	}
	body := result.Messages[0].Content.(*mcp.TextContent).Text
	for _, expected := range []string{
		"skilltrust_prepare_publish_workflow",
		"GitHub Actions OIDC",
		"Preparing the workflow is not a publish.",
		"publish token is the recovery path",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("publish prompt is missing %q:\n%s", expected, body)
		}
	}
}
