package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Resources are what an agent reads before it decides anything. Without them the only way
// to learn this machine's state is to run commands and parse prose, which is how a setup
// gets repeated on a machine that was already set up.
//
// One file under the home is deliberately not a resource: signer.key. There is no reading
// of it that helps, and a private key that can be read over a protocol is a private key that
// ends up in a transcript.
func (s *server) addResources(m *mcp.Server) {
	m.AddResource(&mcp.Resource{
		URI:         "skilltrust://state",
		Name:        "state",
		Title:       "What is set up on this machine",
		Description: "Whether a signing key exists, what keys are pinned, what catalogs are followed, and whether the session hook is installed. Read this first.",
		MIMEType:    "application/json",
	}, s.readState)

	m.AddResource(&mcp.Resource{
		URI:         "skilltrust://identity",
		Name:        "identity",
		Title:       "This machine's public key",
		Description: "The PEM public half of the signing key, which is what a publisher registers and an administrator pins. The private half is never served.",
		MIMEType:    "text/plain",
	}, s.readIdentity)

	m.AddResource(&mcp.Resource{
		URI:         "skilltrust://subscriptions",
		Name:        "subscriptions",
		Title:       "Catalogs this machine follows",
		Description: "Each followed catalog with the keys pinned for it and how many of them must have signed.",
		MIMEType:    "application/json",
	}, s.readFile(filepath.Join(s.home, "catalogs.json"), "[]"))

	m.AddResource(&mcp.Resource{
		URI:         "skilltrust://trusted-keys",
		Name:        "trusted-keys",
		Title:       "Pinned public keys",
		Description: "The keys this machine will accept signatures from, by label.",
		MIMEType:    "application/json",
	}, s.readFile(filepath.Join(s.home, "trusted-keys.json"), "{}"))

	m.AddResource(&mcp.Resource{
		URI:         "skilltrust://guide/setup",
		Name:        "setup-guide",
		Title:       "How SkillTrust is set up, and why each step exists",
		Description: "The procedure, the order it must happen in, and the mistakes that are not obvious from the command names.",
		MIMEType:    "text/markdown",
	}, func(_ context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return text(request.Params.URI, "text/markdown", setupGuide), nil
	})
}

// state is the answer to "what is already done here", which is the question every setup
// starts with and the one no single command answers.
type state struct {
	Home          string              `json:"home"`
	HasSigningKey bool                `json:"has_signing_key"`
	PublicKey     string              `json:"public_key,omitempty"`
	PinnedLabels  []string            `json:"pinned_labels"`
	Subscriptions []stateSubscription `json:"subscriptions"`
	// Approvals is how many signed approvals for individual skills this machine holds.
	//
	// Reported because the state was silent about half the product: a machine following no
	// marketplace but holding fifty approvals looked, in this document, exactly like a
	// machine that had been set up and then abandoned. Most skills on most machines come
	// from a repository or a copy rather than a marketplace, and on Cursor and Antigravity
	// there is no marketplace to come from at all.
	Approvals       int    `json:"skill_approvals"`
	SkillctlPath    string `json:"skillctl_path"`
	SkillctlVersion string `json:"skillctl_version"`
	NextStep        string `json:"next_step"`
}

type stateSubscription struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	CatalogURL string `json:"catalog_url,omitempty"`
	Keys       int    `json:"pinned_keys"`
	Threshold  int    `json:"threshold"`
}

func (s *server) readState(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	current := state{Home: s.home, SkillctlPath: s.run.binary}

	if key, err := os.ReadFile(filepath.Join(s.home, "signer.pub")); err == nil {
		current.HasSigningKey = true
		current.PublicKey = string(key)
	}

	// Counted from the directory rather than verified here: this resource reports what is
	// on the machine, and whether each approval verifies is skilltrust_verify_skills'
	// answer to give. A count that quietly dropped the unverifiable ones would make the
	// most interesting file in the store invisible from the place people look first.
	if entries, err := os.ReadDir(filepath.Join(s.home, "attestations")); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				current.Approvals++
			}
		}
	}

	// The file is {"version": 1, "keys": {...}}, not a flat map. Reading the top level
	// reported "version" and "keys" as pinned labels, which then made the next step wrong:
	// a machine with nothing pinned looked like a machine with two keys pinned.
	current.PinnedLabels = []string{}
	var pinned struct {
		Keys map[string]string `json:"keys"`
	}
	if raw, err := os.ReadFile(filepath.Join(s.home, "trusted-keys.json")); err == nil {
		if json.Unmarshal(raw, &pinned) == nil {
			for label := range pinned.Keys {
				current.PinnedLabels = append(current.PinnedLabels, label)
			}
		}
	}
	sortStrings(current.PinnedLabels)

	current.Subscriptions = []stateSubscription{}
	var followed []struct {
		Name       string   `json:"name"`
		Repository string   `json:"repository"`
		CatalogURL string   `json:"catalog_url"`
		KeyID      string   `json:"key_id"`
		KeyIDs     []string `json:"key_ids"`
		Threshold  int      `json:"threshold"`
	}
	if raw, err := os.ReadFile(filepath.Join(s.home, "catalogs.json")); err == nil {
		_ = json.Unmarshal(raw, &followed)
	}
	for _, one := range followed {
		keys := len(one.KeyIDs)
		if keys == 0 && one.KeyID != "" {
			keys = 1
		}
		threshold := one.Threshold
		if threshold < 1 {
			threshold = 1
		}
		current.Subscriptions = append(current.Subscriptions, stateSubscription{
			Name: one.Name, Repository: one.Repository, CatalogURL: one.CatalogURL,
			Keys: keys, Threshold: threshold,
		})
	}

	if version, err := s.run.run(ctx, "", "version"); err == nil {
		current.SkillctlVersion = firstLine(version.Output)
	}

	current.NextStep = nextStep(current)

	body, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return nil, err
	}
	return text(request.Params.URI, "application/json", string(body)), nil
}

// nextStep names the one thing to do now.
//
// An agent handed a state object will otherwise pick a step that looks plausible, and the
// steps here are order-dependent in a way the command names do not show: subscribing before
// pinning the publisher's key succeeds and follows a catalog nothing can verify.
func nextStep(current state) string {
	switch {
	case !current.HasSigningKey:
		return "Run skilltrust_init. Nothing else works until this machine has a key: it is " +
			"what signs the events a machine files, and its public half is what a publisher registers."
	case len(current.Subscriptions) == 0:
		// Deliberately not keyed on whether anything is pinned. init pins the operator's own
		// key, so a freshly initialised machine already has one label and none of it belongs
		// to a publisher — counting pins would report the next step as done.
		return "Pin the key of the organisation whose catalog you will follow with " +
			"skilltrust_trust_key, then follow it with skilltrust_subscribe. The key has to come " +
			"from somewhere you already trust: a catalog that supplied its own key could replace " +
			"itself, so pinning is what makes the signature mean anything."
	default:
		return "Run skilltrust_check for the plugins your marketplaces sign and " +
			"skilltrust_verify_skills for everything else, then skilltrust_install_hook so it " +
			"happens at the start of every session rather than only when someone remembers."
	}
}

// readFile serves a file under the home, and serves the empty document rather than an error
// when it is not there yet. "Not set up" is a state to report, not a failure to read.
func (s *server) readFile(path, whenMissing string) mcp.ResourceHandler {
	return func(_ context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		raw, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return text(request.Params.URI, "application/json", whenMissing), nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s could not be read: %w", path, err)
		}
		return text(request.Params.URI, "application/json", string(raw)), nil
	}
}

func (s *server) readIdentity(_ context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	raw, err := os.ReadFile(filepath.Join(s.home, "signer.pub"))
	if errors.Is(err, fs.ErrNotExist) {
		return text(request.Params.URI, "text/plain",
			"No key on this machine yet. Run the skilltrust_init tool to create one."), nil
	}
	if err != nil {
		return nil, err
	}
	return text(request.Params.URI, "text/plain", string(raw)), nil
}

func text(uri, mime, body string) *mcp.ReadResourceResult {
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
		{URI: uri, MIMEType: mime, Text: body},
	}}
}
