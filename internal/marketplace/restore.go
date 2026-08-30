package marketplace

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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
func Restore(installed, source, quarantineRoot, name string, now time.Time) (string, error) {
	built, err := signedTree(source)
	if err != nil {
		return "", err
	}

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
