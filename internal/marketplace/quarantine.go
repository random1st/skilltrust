package marketplace

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/random1st/skilltrust/internal/archive"
)

const quarantineTimeLayout = "20060102T150405Z"

// The installed path includes the client home, marketplace, plugin and version. Keeping
// that identity outside the payload prevents two installations of the same name from
// recovering each other's edits, without adding our metadata to the recovered skill.
type quarantineProvenance struct {
	Schema    int    `json:"schema"`
	Installed string `json:"installed"`
	Plugin    string `json:"plugin"`
}

func canonicalInstalledTarget(installed string) (string, error) {
	absolute, err := filepath.Abs(installed)
	if err != nil {
		return "", err
	}
	// Resolve aliases in the client home, but keep the install slot's own identity: its
	// contents are replaced by Restore and must not determine where its history lives.
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func quarantineTargetRoot(root, installed string) string {
	return filepath.Join(root, "by-target", fmt.Sprintf("%x", sha256.Sum256([]byte(installed))))
}

// quarantine moves a directory aside without replacing earlier evidence. The sidecar is
// reserved before the move, so a missing provenance file can never be a successful write.
func quarantine(directory, root, name string, now time.Time) (string, error) {
	if root == "" {
		return "", fmt.Errorf("no quarantine directory configured; refusing to replace %s "+
			"without keeping what was there", directory)
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
		return "", fmt.Errorf("quarantine plugin name must be a single path component")
	}
	installed, err := canonicalInstalledTarget(directory)
	if err != nil {
		return "", err
	}
	base := filepath.Join(quarantineTargetRoot(root, installed), name+"-"+now.UTC().Format(quarantineTimeLayout))
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return "", err
	}
	body, err := json.MarshalIndent(quarantineProvenance{Schema: 1, Installed: installed, Plugin: name}, "", "  ")
	if err != nil {
		return "", err
	}
	for attempt := 0; attempt <= 100; attempt++ {
		target := base
		if attempt > 0 {
			target += "-" + strconv.Itoa(attempt)
		}
		if _, err := os.Lstat(target); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return "", err
		}
		metadata := target + ".json"
		file, err := os.OpenFile(metadata, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, writeErr := file.Write(append(body, '\n'))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(metadata)
			return "", fmt.Errorf("cannot record quarantine provenance: write %v, close %v", writeErr, closeErr)
		}
		if err := os.Rename(directory, target); err != nil {
			_ = os.Remove(metadata)
			return "", err
		}
		return target, nil
	}
	return "", fmt.Errorf("cannot find an unused quarantine name beside %s", base)
}

func isBoundQuarantine(directory string) bool {
	return filepath.Base(filepath.Dir(filepath.Dir(directory))) == "by-target"
}

func checkQuarantineProvenance(directory, installed, plugin string) error {
	metadata := directory + ".json"
	info, err := os.Lstat(metadata)
	if err != nil {
		return fmt.Errorf("cannot read quarantine provenance %s; refusing recovery: %w", metadata, err)
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return fmt.Errorf("invalid quarantine provenance %s; refusing recovery", metadata)
	}
	body, err := os.ReadFile(metadata)
	if err != nil {
		return err
	}
	var provenance quarantineProvenance
	if err := json.Unmarshal(body, &provenance); err != nil {
		return fmt.Errorf("invalid quarantine provenance %s; refusing recovery: %w", metadata, err)
	}
	_, _, validName := quarantineOrder(filepath.Base(directory), provenance.Plugin)
	if provenance.Schema != 1 || provenance.Installed != installed || !validName ||
		(plugin != "" && provenance.Plugin != plugin) ||
		filepath.Base(filepath.Dir(directory)) != fmt.Sprintf("%x", sha256.Sum256([]byte(installed))) {
		return fmt.Errorf("quarantine provenance %s does not match installed target %s; refusing recovery", metadata, installed)
	}
	return nil
}

// InstalledPayload reads exactly the bytes DigestInstalled covers. Recovery review must
// not ask git which files to show, or hide untracked changes the verifier will adopt.
func InstalledPayload(directory string) (*archive.Archive, error) {
	return archive.BuildExcluding(directory, PluginLimits(), excludedRoots()...)
}

// QuarantinePayload resolves one explicitly selected copy and verifies its recorded
// install slot before reading content. Explicit selection cannot turn a legacy filename
// or a symlink into proof that a copy belongs to this client and marketplace.
func QuarantinePayload(quarantined, installed, plugin string) (string, *archive.Archive, error) {
	directory, err := canonicalInstalledTarget(quarantined)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", nil, fmt.Errorf("cannot read quarantined copy %q: %w", directory, err)
	}
	if !info.IsDir() || !isBoundQuarantine(directory) {
		return "", nil, fmt.Errorf("quarantined copy %q has no bound directory provenance; refusing to guess its origin", directory)
	}
	target, err := canonicalInstalledTarget(installed)
	if err != nil {
		return "", nil, err
	}
	if err := checkQuarantineProvenance(directory, target, plugin); err != nil {
		return "", nil, err
	}
	payload, err := InstalledPayload(directory)
	return directory, payload, err
}

// ReclaimVerified recovers the exact reviewed payload, and only over the published bytes
// the caller checked. Keep the old directory until the swap succeeds so a move failure
// cannot discard a fresh edit, dependencies, or session locks.
func ReclaimVerified(quarantined, installed, plugin, reviewedDigest, publishedDigest string) error {
	if reviewedDigest == "" || publishedDigest == "" {
		return fmt.Errorf("recovery requires the reviewed and published payload digests")
	}
	directory, payload, err := QuarantinePayload(quarantined, installed, plugin)
	if err != nil {
		return err
	}
	if payload.Digest != reviewedDigest {
		return fmt.Errorf("quarantined copy %q changed since review; run diff again before adopting it", directory)
	}
	target, err := canonicalInstalledTarget(installed)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(target); err != nil || !info.IsDir() {
		return fmt.Errorf("installed target %q must remain a directory before recovery", target)
	}
	current, err := InstalledPayload(target)
	if err != nil {
		return err
	}
	if current.Digest != publishedDigest {
		return fmt.Errorf("installed copy changed since it was checked; keep that edit before recovering another copy")
	}
	staging, err := os.MkdirTemp(filepath.Dir(target), ".skilltrust-reclaim-*")
	if err != nil {
		return err
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(staging)
		}
	}()
	original := filepath.Join(staging, "original")
	if err := os.Rename(target, original); err != nil {
		return err
	}
	keepStaging = true
	var moved []string
	rollback := func(cause error) error {
		cause = errors.Join(cause, returnClientManaged(original, directory, moved))
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return errors.Join(cause, fmt.Errorf("cannot return original over a new entry at %q; original remains in %q", target, original))
		}
		if err := os.Rename(original, target); err != nil {
			return errors.Join(cause, fmt.Errorf("cannot return original: %w; original remains in %q", err, original))
		}
		keepStaging = false
		return cause
	}
	// Check after the atomic move too: an edit made after reconciliation must come back
	// unchanged instead of being discarded as if it were still the published copy.
	current, err = InstalledPayload(original)
	if err != nil {
		return rollback(err)
	}
	if current.Digest != publishedDigest {
		return rollback(fmt.Errorf("installed copy changed since it was checked; keep that edit before recovering another copy"))
	}
	for _, name := range ClientManagedRoots {
		from, to := filepath.Join(original, name), filepath.Join(directory, name)
		if _, err := os.Lstat(from); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return rollback(err)
		}
		if _, err := os.Lstat(to); !os.IsNotExist(err) {
			return rollback(fmt.Errorf("cannot replace client-managed entry %q; both copies are preserved", to))
		}
		if err := os.Rename(from, to); err != nil {
			return rollback(err)
		}
		moved = append(moved, name)
	}
	// Client entries are excluded from identity, so this also catches a saved payload
	// edited while dependencies were being moved without mistaking those moves for edits.
	_, payload, err = QuarantinePayload(directory, target, plugin)
	if err != nil {
		return rollback(err)
	}
	if payload.Digest != reviewedDigest {
		return rollback(fmt.Errorf("quarantined copy changed during recovery; run diff again"))
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return rollback(fmt.Errorf("another entry appeared at %q during recovery", target))
	}
	if err := os.Rename(directory, target); err != nil {
		return rollback(err)
	}
	keepStaging = false
	return nil
}

// NewestQuarantine returns only history bound to this exact install slot. A flat legacy
// name cannot prove its origin, even if only one marketplace is currently installed: the
// other installation may have been removed or belong to another client home.
func NewestQuarantine(root, installed, plugin string) (string, bool, error) {
	target, err := canonicalInstalledTarget(installed)
	if err != nil {
		return "", false, err
	}
	entries, err := os.ReadDir(quarantineTargetRoot(root, target))
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	var newest string
	var newestTime time.Time
	var newestSequence int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		directory := filepath.Join(quarantineTargetRoot(root, target), entry.Name())
		if err := checkQuarantineProvenance(directory, target, plugin); err != nil {
			return "", false, err
		}
		when, sequence, _ := quarantineOrder(entry.Name(), plugin)
		if newest == "" || when.After(newestTime) || (when.Equal(newestTime) && sequence > newestSequence) {
			newest, newestTime, newestSequence = directory, when, sequence
		}
	}
	if newest != "" {
		return newest, true, nil
	}
	entries, err = os.ReadDir(root)
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	var legacy []string
	for _, entry := range entries {
		if _, _, ok := quarantineOrder(entry.Name(), plugin); entry.IsDir() && ok {
			legacy = append(legacy, filepath.Join(root, entry.Name()))
		}
	}
	if len(legacy) > 0 {
		return "", false, fmt.Errorf("legacy quarantine has no recorded installed target; refusing to guess for %s. "+
			"Inspect these copies and recover the chosen path explicitly: %s", installed, strings.Join(legacy, ", "))
	}
	return "", false, nil
}

// Compare the collision counter numerically: the eleventh restore in one second is newer
// than the tenth, despite "-10" sorting before "-9" as text.
func quarantineOrder(name, plugin string) (time.Time, int, bool) {
	rest, ok := strings.CutPrefix(name, plugin+"-")
	if !ok || plugin == "" || len(rest) < len(quarantineTimeLayout) {
		return time.Time{}, 0, false
	}
	when, err := time.Parse(quarantineTimeLayout, rest[:len(quarantineTimeLayout)])
	if err != nil {
		return time.Time{}, 0, false
	}
	suffix := rest[len(quarantineTimeLayout):]
	if suffix == "" {
		return when, 0, true
	}
	if !strings.HasPrefix(suffix, "-") {
		return time.Time{}, 0, false
	}
	sequence, err := strconv.Atoi(suffix[1:])
	return when, sequence, err == nil && sequence > 0
}
