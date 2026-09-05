package marketplace

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/archive"
)

// Restore replaces an installed plugin with the bytes its publisher signed, keeping what the
// client owns, and returns where the replaced copy was kept.
//
// The obvious implementation — swap the directory — is wrong here, and wrong in a way that
// would only show up on someone else's machine. The installed copy is not purely the
// publisher's: Claude Code installs npm dependencies into it after fetching and writes an
// `.in_use` marker while a session holds it. Replacing the directory wholesale would delete
// a plugin's dependencies, breaking it, and would pull a file out from under a running
// session. So the signed tree is laid down fresh and the client's own entries are carried
// across.
//
// The replaced copy is kept rather than deleted. Restoring without it destroys the evidence
// in the one case that is an incident, which is the case this exists for.
//
// This compatibility wrapper preserves the pre-digest-binding API for callers that have no
// signed digest to compare against. Callers restoring from a signed catalog should use
// RestoreVerified so the bytes written are bound to the catalog entry they are supposed to
// restore.
func Restore(installed, source, quarantineRoot, name string, now time.Time) (string, error) {
	return RestoreVerified(installed, source, quarantineRoot, name, now, "")
}

// RestoreVerified restores from a local source checkout only when the archive it builds is
// still exactly the digest the caller expects from a signed catalog entry.
func RestoreVerified(
	installed, source, quarantineRoot, name string, now time.Time, expectedDigest string,
) (string, error) {
	built, err := signedTree(source)
	if err != nil {
		return "", err
	}
	if expectedDigest != "" && !strings.EqualFold(built.Digest, expectedDigest) {
		return "", fmt.Errorf("local source digest %s does not match the signed %s",
			built.Digest, expectedDigest)
	}
	return restoreBuilt(installed, quarantineRoot, name, now, built)
}

func restoreBuilt(
	installed, quarantineRoot, name string, now time.Time, built *archive.Archive,
) (string, error) {
	parent := filepath.Dir(installed)
	staging, err := os.MkdirTemp(parent, ".skilltrust-staging-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)

	unpacked := filepath.Join(staging, "payload")
	if _, err := archive.ExtractVerified(
		built.Payload, unpacked, built.Digest, PluginLimits()); err != nil {
		return "", err
	}

	// Carry across what the client maintains, before anything is moved aside. Copying rather
	// than moving would double the disk cost of a node_modules tree for no gain; moving is
	// safe because the directory it comes from is about to be quarantined anyway.
	for _, name := range ClientManagedRoots {
		from := filepath.Join(installed, name)
		if _, err := os.Lstat(from); err != nil {
			continue
		}
		if err := os.Rename(from, filepath.Join(unpacked, name)); err != nil {
			return "", fmt.Errorf("cannot preserve %s: %w", name, err)
		}
	}

	quarantined, err := quarantine(installed, quarantineRoot, name, now)
	if err != nil {
		return "", err
	}
	if err := os.Rename(unpacked, installed); err != nil {
		return "", err
	}
	return quarantined, nil
}

// signedTree builds the archive of what a publisher signs: git-tracked files, without the
// entries the client owns. It must agree exactly with DigestPlugin, or a restore would write
// bytes that then fail their own verification.
func signedTree(source string) (*archive.Archive, error) {
	var keep func(string) bool
	if tracked := trackedFiles(source); tracked != nil {
		keep = func(path string) bool { _, ok := tracked[path]; return ok }
	}
	return archive.BuildFiltered(source, PluginLimits(), keep, excludedRoots()...)
}

// MaterializeVerifiedMarketplace writes one signed plugin into a minimal marketplace tree.
//
// It exists for the first-install path: the native client knows how to install from a
// marketplace path, while the security boundary here is a single managed plugin digest.
// Passing a whole checkout would let unsigned sibling entries and later edits ride along,
// so the approved bytes are re-materialized into a marketplace that exposes exactly one
// plugin and nothing else.
func MaterializeVerifiedMarketplace(
	destination, marketplaceName string, plugin catalog.Managed, source string,
) error {
	for _, part := range []string{marketplaceName, plugin.Name, plugin.Version} {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\\\x00\r\n") {
			return fmt.Errorf("marketplace, plugin and version must be single path components")
		}
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(plugin.Digest, "sha256:"))
	if !strings.HasPrefix(plugin.Digest, "sha256:") || err != nil || len(digest) != 32 {
		return fmt.Errorf("a signed SHA-256 plugin digest is required before installation")
	}
	built, err := signedTree(source)
	if err != nil {
		return err
	}
	if !strings.EqualFold(built.Digest, plugin.Digest) {
		return fmt.Errorf("local source digest %s does not match the signed %s",
			built.Digest, plugin.Digest)
	}
	return writeMaterializedMarketplace(destination, marketplaceName, plugin, built)
}

func writeMaterializedMarketplace(
	destination, marketplaceName string, plugin catalog.Managed, built *archive.Archive,
) error {
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".skilltrust-marketplace-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	root := filepath.Join(staging, "snapshot")
	pluginRoot := filepath.Join(root, "plugins", plugin.Name)
	if _, err := archive.ExtractVerified(
		built.Payload, pluginRoot, built.Digest, PluginLimits()); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, ".claude-plugin"), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(struct {
		Name    string            `json:"name"`
		Owner   map[string]string `json:"owner"`
		Plugins []struct {
			Name    string `json:"name"`
			Source  string `json:"source"`
			Version string `json:"version,omitempty"`
		} `json:"plugins"`
	}{
		Name:  marketplaceName,
		Owner: map[string]string{"name": marketplaceName},
		Plugins: []struct {
			Name    string `json:"name"`
			Source  string `json:"source"`
			Version string `json:"version,omitempty"`
		}{
			{Name: plugin.Name, Source: "./plugins/" + plugin.Name, Version: plugin.Version},
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(
		filepath.Join(root, ManifestPath), append(body, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.RemoveAll(destination); err != nil {
		return err
	}
	return os.Rename(root, destination)
}

// Reclaim puts a quarantined copy back as the installed one: the recovery half of Restore.
//
// It exists because the advertised path out of a restore dead-ended. The hint said "adopt
// this to keep it", but by the time anyone reads a hint the restore has already happened —
// the person's bytes are in quarantine, the installed copy matches what was published, and
// adopt truthfully answers that there is nothing to adopt. The way back was hand-copying a
// directory nobody would guess the name of.
//
// The client-managed entries currently installed move into the reclaimed tree first, for
// the same reason Restore carries them the other way: they were made after the quarantined
// copy was set aside, and losing them breaks the plugin or drops live session locks. The
// published bytes being discarded are re-materialisable from the marketplace checkout, so
// nothing is quarantined here.
func Reclaim(quarantined, installed string) error {
	if _, err := os.Stat(quarantined); err != nil {
		return fmt.Errorf("nothing to take back: %w", err)
	}
	for _, name := range ClientManagedRoots {
		from := filepath.Join(installed, name)
		if _, err := os.Lstat(from); err != nil {
			continue
		}
		if err := os.Rename(from, filepath.Join(quarantined, name)); err != nil {
			return fmt.Errorf("cannot preserve %s: %w", name, err)
		}
	}
	if err := os.RemoveAll(installed); err != nil {
		return err
	}
	return os.Rename(quarantined, installed)
}

// quarantine moves a directory aside under a timestamped name, never replacing one already
// there: the earlier directory is the earlier evidence.
func quarantine(directory, root, name string, now time.Time) (string, error) {
	if root == "" {
		return "", fmt.Errorf("no quarantine directory configured; refusing to replace %s "+
			"without keeping what was there", directory)
	}
	base := filepath.Join(root, name+"-"+now.Format("20060102T150405Z"))
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return "", err
	}
	target := base
	for attempt := 1; ; attempt++ {
		if _, err := os.Lstat(target); os.IsNotExist(err) {
			break
		}
		if attempt > 100 {
			return "", fmt.Errorf("cannot find an unused quarantine name beside %s", base)
		}
		target = fmt.Sprintf("%s-%d", base, attempt)
	}
	if err := os.Rename(directory, target); err != nil {
		return "", err
	}
	return target, nil
}
