package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
)

// curatorLedgerName is the record Hermes's own curator keeps beside the skills it changes.
const curatorLedgerName = ".curator_ledger.jsonl"

// maxCuratorLedgerBytes bounds the file. It is append-only and written by another program, so
// a check that runs on a schedule must not be the thing that reads a runaway log into memory.
const maxCuratorLedgerBytes = 8 << 20

// curatorRecord is one line of the ledger: who changed a skill, when, why, and the exact
// bytes that were left behind.
//
// Only the fields that carry a decision are decoded. The file belongs to another product and
// will grow fields; refusing to parse it the first time one appears would turn every
// legitimate curator edit back into a tampering report.
type curatorRecord struct {
	Timestamp string `json:"ts"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Skill     string `json:"skill"`
	Evidence  struct {
		SessionID string `json:"session_id"`
	} `json:"evidence"`
	After []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"after"`
}

// reason is what the report shows in place of a person's own words.
//
// It names the ledger rather than pretending somebody typed it here, because they did not:
// the claim is "Hermes's curator recorded making this change", and an adoption whose reason
// could be mistaken for a human decision would be the tool putting words in someone's mouth.
func (r curatorRecord) reason() string {
	reason := fmt.Sprintf("curator ledger: %s %s %s", r.Actor, r.Action, r.Timestamp)
	if r.Evidence.SessionID != "" {
		reason += " session " + r.Evidence.SessionID
	}
	return reason
}

func (r curatorRecord) since() time.Time {
	when, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		return time.Time{}
	}
	return when.UTC()
}

// readCuratorLedger returns the newest record for each skill in one skills root.
//
// The newest wins because the file is append-only: an earlier record describes bytes that
// have since been replaced, and honouring it would vouch for a state that no longer exists.
// A line that does not parse is skipped rather than fatal — the ledger is another program's
// file, and one malformed line must not decide that every curated skill on the host is
// tampering.
func readCuratorLedger(root string) map[string]curatorRecord {
	file, err := os.Open(filepath.Join(root, curatorLedgerName))
	if err != nil {
		return nil
	}
	defer file.Close()

	latest := map[string]curatorRecord{}
	scanner := bufio.NewScanner(io.LimitReader(file, maxCuratorLedgerBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record curatorRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Skill == "" {
			continue
		}
		latest[record.Skill] = record
	}
	return latest
}

// curatorLedgerAdoptions turns what Hermes's curator recorded into adoptions for this run.
//
// The point of it is that a Hermes host edits its own skills as a matter of course: its
// curator patches one to fit the host and writes down that it did. Reporting those edits as
// tampering would bury the real finding among the ordinary ones, and a report nobody can read
// protects nothing.
//
// Nothing here is written to the adoptions file, and that is the design rather than an
// omission. The ledger is the record; these are derived from it and from the bytes on disk
// every time, so an edit made after the curator's last entry makes the adoption disappear by
// itself. A persisted copy would outlive the evidence for it, which is exactly the state
// adopting exists to avoid.
func curatorLedgerAdoptions(
	snapshot *catalog.Snapshot, roots []marketplace.SkillRoot, locate marketplace.Locator,
) marketplace.Adoptions {
	ledgers := make(map[string]map[string]curatorRecord, len(roots))
	for _, root := range roots {
		ledgers[root.Label] = readCuratorLedger(root.Path)
	}

	var adoptions marketplace.Adoptions
	for _, managed := range snapshot.Skills {
		for _, copy := range locate(managed) {
			record, found := ledgers[copy.Label][managed.Name]
			if !found || !ledgerCovers(record, copy.Path) {
				continue
			}
			digest, _, err := marketplace.DigestInstalled(copy.Path)
			if err != nil {
				continue
			}
			adoptions.Entries = append(adoptions.Entries, marketplace.Adoption{
				Marketplace: snapshot.Name, Plugin: managed.Name, Copy: copy.Label,
				From: managed.Digest, Local: digest,
				Since: record.since(), Reason: record.reason(),
			})
		}
	}
	return adoptions
}

// ledgerCovers reports whether a record accounts for every byte currently in a skill
// directory.
//
// This is the whole strength of the mechanism, so it is deliberately unforgiving in one
// direction: every file on disk must appear in the record with the digest the record claims,
// and every file the record claims must still be there. A record that covers most of a
// directory covers nothing — otherwise anything able to add a file beside a curated skill
// would inherit the curator's word for it, which is the trust this reads from the ledger
// being handed to whoever wrote last.
//
// Entries naming a path outside the directory are ignored rather than refused. The ledger
// records absolute paths and a skill's record has no business elsewhere, but a stray one must
// not be able to veto an adoption; the requirement that every file on disk be vouched for is
// what does the work here.
func ledgerCovers(record curatorRecord, directory string) bool {
	claimed := map[string]string{}
	for _, prefix := range ledgerPrefixes(directory) {
		for _, after := range record.After {
			relative, inside := relativeUnder(prefix, after.Path)
			if !inside {
				continue
			}
			claimed[relative] = strings.ToLower(after.SHA256)
		}
	}
	if len(claimed) == 0 {
		return false
	}

	seen := 0
	walked := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		// Only regular files can be compared to a digest. Anything else in a skill directory
		// is not something the ledger described, so it is not covered.
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		want, listed := claimed[filepath.ToSlash(relative)]
		if !listed {
			return fmt.Errorf("%s is not in the ledger", relative)
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if sum != want {
			return fmt.Errorf("%s does not match the ledger", relative)
		}
		seen++
		return nil
	})
	return walked == nil && seen == len(claimed)
}

// ledgerPrefixes are the spellings of a directory a recorded absolute path might use. The
// resolved one is included because a host reaches its skills through a symlinked root often
// enough — /var against /private/var, a profile directory linked into place — and a record
// written through one spelling must still be readable from the other.
func ledgerPrefixes(directory string) []string {
	prefixes := []string{filepath.Clean(directory)}
	if resolved, err := filepath.EvalSymlinks(directory); err == nil &&
		filepath.Clean(resolved) != prefixes[0] {
		prefixes = append(prefixes, filepath.Clean(resolved))
	}
	return prefixes
}

// relativeUnder returns a recorded path relative to a directory, and whether it is inside it.
func relativeUnder(directory, recorded string) (string, bool) {
	if recorded == "" {
		return "", false
	}
	relative, err := filepath.Rel(directory, filepath.Clean(recorded))
	if err != nil {
		return "", false
	}
	relative = filepath.ToSlash(relative)
	if relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", false
	}
	return relative, true
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, maxCuratorLedgerBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// mergeAdoptions puts derived adoptions behind the ones a person wrote.
//
// A record in the adoptions file is somebody's decision, made deliberately and kept. One
// derived from a ledger is this tool's reading of another program's log. Where both describe
// the same copy of the same skill, the person's wins — they are the only one of the two who
// can be asked what they meant.
func mergeAdoptions(owned, derived marketplace.Adoptions) marketplace.Adoptions {
	merged := marketplace.Adoptions{Entries: append([]marketplace.Adoption{}, owned.Entries...)}
	for _, entry := range derived.Entries {
		taken := false
		for _, existing := range owned.Entries {
			if existing.Marketplace == entry.Marketplace && existing.Plugin == entry.Plugin &&
				existing.Copy == entry.Copy {
				taken = true
				break
			}
		}
		if !taken {
			merged.Entries = append(merged.Entries, entry)
		}
	}
	return merged
}
