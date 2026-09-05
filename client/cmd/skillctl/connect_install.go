package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/internal/source"
)

const connectNativeInstallTimeout = 30 * time.Second

var (
	connectNativeLookPath = exec.LookPath
	connectNativeCommand  = func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, name, arguments...)
		command.WaitDelay = 250 * time.Millisecond
		return command.CombinedOutput()
	}
)

type managedInstallCandidate struct {
	marketplace  string
	sourcePlugin string
	plugin       catalog.Managed
}

// ensureFirstManagedPlugin bootstraps the empty-cache case for managed clients.
//
// Once any catalog-managed version is on disk, the normal managed check is the source of
// truth about whether it is verified, changed or revoked. This helper only does the one
// thing that check cannot do by itself: ask a native client to install the first signed
// plugin from a frozen, SkillTrust-owned copy of the already-verified bytes.
func ensureFirstManagedPlugin(known agent) error {
	if !known.Managed {
		return fmt.Errorf("%s has no managed marketplace cache to install into", known.Name)
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return fmt.Errorf("cannot load the followed catalogs: %w", err)
	}
	if len(subscriptions) == 0 {
		return fmt.Errorf("no followed catalog is available to install from yet")
	}

	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return err
	}

	var candidate *managedInstallCandidate
	var issues []string
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, connectNow())
		if err != nil {
			issues = append(issues,
				fmt.Sprintf("%s could not be verified again: %v", subscription.Name, err))
			continue
		}
		for _, managed := range snapshot.Skills {
			installed := marketplace.InstalledPath(known.Home(), snapshot.Name,
				managed.Name, managed.Version)
			if info, err := os.Stat(installed); err == nil && info.IsDir() {
				return nil
			}
			if candidate != nil {
				continue
			}
			next, err := firstManagedInstallCandidate(subscription, snapshot, managed)
			if err != nil {
				issues = append(issues, err.Error())
				continue
			}
			candidate = next
		}
	}
	if candidate == nil {
		message := "no followed catalog had verified local plugin bytes ready to install"
		if len(issues) > 0 {
			message += ": " + issues[0]
		}
		return fmt.Errorf("%s", message)
	}
	return installManagedPlugin(known, *candidate)
}

func firstManagedInstallCandidate(
	subscription Subscription,
	snapshot *catalog.Snapshot,
	managed catalog.Managed,
) (*managedInstallCandidate, error) {
	if _, revoked := snapshot.IsRevoked(managed.Digest); revoked {
		return nil, fmt.Errorf("%s/%s is revoked and cannot be installed",
			snapshot.Name, managed.Name)
	}
	if managed.Version == "" {
		return nil, fmt.Errorf("%s/%s has no installable version in the signed catalog",
			snapshot.Name, managed.Name)
	}

	sourceRoot := source.Path(catalogRoot(), subscription.Name)
	manifest, err := marketplace.Load(sourceRoot)
	if err != nil {
		return nil, fmt.Errorf("%s has no readable local marketplace checkout: %w",
			subscription.Name, err)
	}
	if manifest.Name != snapshot.Name {
		return nil, fmt.Errorf("%s declares marketplace %q, but the signed catalog says %q",
			sourceRoot, manifest.Name, snapshot.Name)
	}

	for _, entry := range manifest.Plugins {
		if entry.Name != managed.Name {
			continue
		}
		version := entry.ResolveVersion(sourceRoot)
		if version != managed.Version {
			return nil, fmt.Errorf("%s/%s resolves to version %q, but the signed catalog expects %q",
				snapshot.Name, managed.Name, version, managed.Version)
		}
		pluginRoot, local := entry.LocalPath(sourceRoot)
		if !local {
			return nil, fmt.Errorf("%s/%s is not local to the verified checkout",
				snapshot.Name, managed.Name)
		}
		digest, _, err := marketplace.DigestPlugin(pluginRoot)
		if err != nil {
			return nil, fmt.Errorf("%s/%s cannot be digested for install: %w",
				snapshot.Name, managed.Name, err)
		}
		if digest != managed.Digest {
			return nil, fmt.Errorf("%s/%s no longer matches the signed catalog digest",
				snapshot.Name, managed.Name)
		}
		return &managedInstallCandidate{
			marketplace:  manifest.Name,
			sourcePlugin: pluginRoot,
			plugin:       managed,
		}, nil
	}

	return nil, fmt.Errorf("%s/%s is not listed in the verified marketplace checkout",
		snapshot.Name, managed.Name)
}

func installManagedPlugin(known agent, candidate managedInstallCandidate) error {
	if known.Name != "claude" {
		return fmt.Errorf("skillctl can verify %s marketplace plugins once one is installed, but it cannot ask %s to install the first one yet. Install %s@%s with the native %s CLI and run skillctl connect again",
			known.Name, known.Name, candidate.plugin.Name, candidate.marketplace, known.Name)
	}
	if _, err := connectNativeLookPath("claude"); err != nil {
		return fmt.Errorf("Claude Code is configured here, but the claude CLI is not on PATH: %w", err)
	}

	snapshotRoot, err := materializeManagedInstallSnapshot(candidate)
	if err != nil {
		return err
	}
	if err := runNativeManagedInstall("claude", "plugin", "marketplace", "add",
		"--scope", "user", snapshotRoot); err != nil {
		return fmt.Errorf("Claude could not add the verified marketplace snapshot %q: %w",
			snapshotRoot, err)
	}
	if err := confirmNativeMarketplace(candidate.marketplace, snapshotRoot); err != nil {
		return err
	}
	if err := runNativeManagedInstall("claude", "plugin", "install", "--scope", "user",
		candidate.plugin.Name+"@"+candidate.marketplace); err != nil {
		return fmt.Errorf("Claude could not install %s@%s from the verified marketplace snapshot: %w",
			candidate.plugin.Name, candidate.marketplace, err)
	}
	return nil
}

// Adding an already configured marketplace is idempotent, but its name may
// still resolve to another source. Verify the native resolver before installation.
func confirmNativeMarketplace(name, snapshotRoot string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectNativeInstallTimeout)
	defer cancel()
	raw, err := connectNativeCommand(ctx, "claude", "plugin", "marketplace", "list", "--json")
	if err != nil {
		return fmt.Errorf("Claude could not confirm its marketplace source: %w", err)
	}
	var entries []struct {
		Name            string `json:"name"`
		Source          string `json:"source"`
		Path            string `json:"path"`
		InstallLocation string `json:"installLocation"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return fmt.Errorf("Claude returned an unreadable marketplace list: %w", err)
	}
	for _, entry := range entries {
		if entry.Name != name {
			continue
		}
		if entry.Source == "directory" && filepath.Clean(entry.Path) == filepath.Clean(snapshotRoot) && filepath.Clean(entry.InstallLocation) == filepath.Clean(snapshotRoot) {
			return nil
		}
		return fmt.Errorf("Claude already uses another source for %s; review that marketplace in Claude before running skillctl connect again", name)
	}
	return fmt.Errorf("Claude did not register the verified %s marketplace; run skillctl connect again", name)
}

func materializeManagedInstallSnapshot(candidate managedInstallCandidate) (string, error) {
	digestKey := strings.NewReplacer(":", "-", "/", "-").Replace(strings.ToLower(candidate.plugin.Digest))
	target := filepath.Join(Home(), "install-snapshots", candidate.marketplace,
		candidate.plugin.Name, candidate.plugin.Version, digestKey)
	if err := marketplace.MaterializeVerifiedMarketplace(target,
		candidate.marketplace, candidate.plugin, candidate.sourcePlugin); err != nil {
		return "", fmt.Errorf("cannot prepare a verified marketplace snapshot for %s@%s: %w",
			candidate.plugin.Name, candidate.marketplace, err)
	}
	return target, nil
}

func runNativeManagedInstall(name string, arguments ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectNativeInstallTimeout)
	defer cancel()

	output, err := connectNativeCommand(ctx, name, arguments...)
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		if ctx.Err() != nil {
			return fmt.Errorf("%w after %s", ctx.Err(), connectNativeInstallTimeout)
		}
		return err
	}
	return fmt.Errorf("%w: %s", err, trimmed)
}
