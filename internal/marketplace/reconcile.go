package marketplace

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/random1st/skilltrust/catalog"
)

// Outcome is what a reconciliation found for one signed plugin.
//
// Installing is deliberately absent. Claude Code owns installation, and a tool that put
// plugins into its cache behind its back would be fighting the client rather than checking
// it — the cache is a copy the client made and expects to manage. What is left is the part
// nobody does: confirming the copy is still what was signed, and putting it back when it is
// not.
type Outcome string

const (
	// OutcomeVerified means the installed copy is byte-identical to what was signed.
	OutcomeVerified Outcome = "verified"
	// OutcomeAbsent means this machine did not install the plugin. Not every machine takes
	// every plugin a catalog offers, so this is ordinary and is not a finding.
	OutcomeAbsent Outcome = "absent"
	// OutcomeChanged means the installed copy differs from the signature.
	OutcomeChanged Outcome = "changed"
	// OutcomeRestored means it differed and was put back.
	OutcomeRestored Outcome = "restored"
	// OutcomeRevoked means the signed digest is revoked, so the plugin must not run.
	OutcomeRevoked Outcome = "revoked"
	// OutcomeOtherVersion means a different release is installed. That is a choice about
	// which version to run, not a difference to correct.
	OutcomeOtherVersion Outcome = "other version"
	// OutcomeUnverifiable means no claim can be made: unreadable, or nothing to restore from.
	OutcomeUnverifiable Outcome = "unverifiable"
	// OutcomeAdapted means the copy differs from the signature and the person at this
	// machine said so on purpose.
	//
	// Without this, editing a skill to fit your setup — the most ordinary thing anyone does
	// with one — put the file in quarantine and the published version back, every session,
	// silently. A tool that undoes your work every morning is a tool you uninstall, and an
	// uninstalled checker protects nothing at all.
	//
	// It is never quiet. An adapted plugin is reported like any other finding, so an
	// organisation can see which machines run bytes nobody signed.
	OutcomeAdapted Outcome = "adapted"
)

// Settled reports whether an outcome needs no attention and no words. Adapted is not
// settled: it is a normal state, not an invisible one.
func (o Outcome) Settled() bool { return o == OutcomeVerified || o == OutcomeAbsent }

// Result is one line of a reconciliation.
type Result struct {
	Marketplace string `json:"marketplace"`
	// ClientHome is only for local recovery commands. Private filesystem paths must
	// not become part of a check uploaded to the organisation.
	ClientHome string  `json:"-"`
	Plugin     string  `json:"plugin"`
	Version    string  `json:"version"`
	Outcome    Outcome `json:"outcome"`
	Signed     string  `json:"signed,omitempty"`
	OnDisk     string  `json:"on_disk,omitempty"`
	Installed  string  `json:"installed_version,omitempty"`
	Detail     string  `json:"detail,omitempty"`
	Quarantine string  `json:"quarantine,omitempty"`
	// Adapted carries the reason the person gave when they adopted these bytes, and
	// AdaptedSince when they did. The date is reported, never enforced: an adoption that
	// expired on a timer would ask for a re-approval carrying no new information, and a
	// re-approval that says nothing is one people learn to click through. What it is for
	// is letting an organisation see a temporary workaround that has been temporary for
	// fourteen months.
	Adapted      string    `json:"adapted,omitempty"`
	AdaptedSince time.Time `json:"adapted_since,omitempty"`
	// Lapsed marks a difference that used to be adopted and no longer is. A reporter must
	// tell these two apart: after a plain edit, "adopt this to keep it" is the right
	// advice; after a lapse the person's bytes are already in quarantine, so adopting now
	// would adopt the publisher's copy — the opposite of what they wanted.
	Lapsed bool `json:"lapsed,omitempty"`
	// Copy names which of several copies of one published skill this line is about, and is
	// empty when the client keeps exactly one. A client that reads skills from more than one
	// directory — one per agent profile, say — has a copy per directory, each of which can
	// verify, differ or be adopted on its own. Without this, two lines would be identical
	// text about different files and neither could be acted on.
	Copy string `json:"copy,omitempty"`
}

// InstalledCopy is one copy of a published skill on this machine.
//
// Path and Label describe the copy; OtherVersion describes its absence. Keeping the second
// case here rather than in the reconciler is what lets the reconciler stay ignorant of
// versioned caches: only a client that installs releases side by side can find a different
// one in the place it looked, so only its locator can say so.
type InstalledCopy struct {
	// Path is the directory holding this copy.
	Path string
	// Label distinguishes copies of one skill within one client, and is empty when there is
	// only ever one. It is reported, so it must be something a person recognises — a profile
	// name rather than a hash of a path.
	Label string
	// OtherVersion names the release found where the published one was expected, for a
	// client that installs releases side by side. Set only when Path is empty.
	OtherVersion string
}

// Locator answers where a published skill's copies are on this machine.
//
// It exists so that reconciling does not have to know how any client stores what it
// installed. Claude Code and Codex keep a versioned plugin cache; a client with loose skill
// directories keeps one directory per profile and no versions at all. Both are a list of
// directories to digest, and everything after that point — digesting, verifying, restoring,
// reporting — is the same work.
type Locator func(managed catalog.Managed) []InstalledCopy

// Options configures a reconciliation.
type Options struct {
	// ClaudeHome is where the plugin cache lives.
	ClaudeHome string
	// Source is the verified marketplace checkout to restore from. Empty means the machine
	// can report but not repair.
	Source string
	// QuarantineRoot is where a replaced copy is kept.
	QuarantineRoot string
	// Restore turns reporting into repair.
	Restore bool
	// Adopted are the differences this machine's owner accepted on purpose. Empty means
	// every difference is a finding, which is the behaviour every machine had before.
	Adopted Adoptions
	// Locate finds the copies of a published skill this client keeps. Nil is the plugin
	// cache under ClaudeHome, which is what every caller wanted before a second shape of
	// client existed.
	Locate Locator
	Now    time.Time
}

// Reconcile checks every plugin a signed marketplace claims, and optionally repairs it.
func Reconcile(snapshot *catalog.Snapshot, options Options) []Result {
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	manifest, _ := Load(options.Source)
	locate := options.Locate
	if locate == nil {
		locate = PluginCache(options.ClaudeHome, snapshot.Name)
	}

	results := make([]Result, 0, len(snapshot.Skills))
	for _, managed := range snapshot.Skills {
		copies := locate(managed)
		if len(copies) == 0 {
			// Nothing installed here is an ordinary answer and still owes a line, or a
			// catalog entry would silently disappear from the report.
			results = append(results, reconcileOne(snapshot, managed, manifest, options, InstalledCopy{}))
			continue
		}
		for _, copy := range copies {
			results = append(results, reconcileOne(snapshot, managed, manifest, options, copy))
		}
	}
	// Copy breaks the tie, so several copies of one skill keep a stable order between runs
	// rather than shuffling and reading as a change.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Plugin != results[j].Plugin {
			return results[i].Plugin < results[j].Plugin
		}
		return results[i].Copy < results[j].Copy
	})
	return results
}

func reconcileOne(
	snapshot *catalog.Snapshot, managed catalog.Managed, manifest *Manifest, options Options,
	copy InstalledCopy,
) Result {
	home, _ := filepath.Abs(options.ClaudeHome)
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}
	result := Result{
		Marketplace: snapshot.Name, Plugin: managed.Name,
		ClientHome: home, Copy: copy.Label,
		Version: managed.Version, Signed: managed.Digest,
	}

	// Revocation is answered first and outranks everything, including a perfectly good
	// signature: a signature is a statement about the past and a revocation about now.
	if entry, revoked := snapshot.IsRevoked(managed.Digest); revoked {
		result.Outcome, result.Detail = OutcomeRevoked, entry.Reason
		return result
	}

	if copy.Path == "" {
		if copy.OtherVersion == "" {
			result.Outcome = OutcomeAbsent
			return result
		}
		result.Outcome, result.Installed = OutcomeOtherVersion, copy.OtherVersion
		// The version the catalog signs is the only one this reconciler digests, so an
		// adoption of the installed release is never examined again once the publisher
		// moves on. Left unsaid, that is a silent end to something a person decided on
		// purpose — the line about the version difference must also say what it did to
		// their adoption.
		if adoption, ok := options.Adopted.FindCopy(snapshot.Name, managed.Name, copy.Label); ok {
			result.Detail = fmt.Sprintf(
				"you adopted a change to %s (%s); the catalog has moved to %s — "+
					"re-apply your change there and adopt it again, if you still want it",
				copy.OtherVersion, adoption.Reason, managed.Version)
		}
		return result
	}

	installed := copy.Path
	digest, _, err := DigestInstalled(installed)
	if err != nil {
		result.Outcome, result.Detail = OutcomeUnverifiable, err.Error()
		return result
	}
	result.OnDisk = digest
	// The copy on disk has its own identity, and that identity can be revoked even when
	// the published one is not. This is the only lever an organisation has against bytes a
	// machine adopted: revoking the digest the dashboard shows must stop those bytes, or
	// the one mechanism for withdrawing a bad skill is inert on exactly the machines that
	// edited it. Answered before the adoption branch, so revocation outranks adoption.
	if entry, revoked := snapshot.IsRevoked(digest); revoked {
		result.Outcome, result.Detail = OutcomeRevoked, entry.Reason
		return result
	}
	if digest == managed.Digest {
		result.Outcome = OutcomeVerified
		return result
	}

	// An adoption is a claim about exact bytes, not a licence to diverge. It applies only
	// while the local copy is still the copy that was adopted AND the catalog still
	// publishes the digest it was adopted away from. Anything else — someone editing the
	// file again, or upstream shipping a new version — falls back to being a difference
	// that needs a decision, which is the property that keeps this from being an off switch.
	if adoption, ok := options.Adopted.FindCopy(snapshot.Name, managed.Name, copy.Label); ok {
		switch {
		case adoption.Local != digest:
			result.Lapsed = true
			result.Detail = "these are not the bytes that were adopted; they changed again since"
		case adoption.From != managed.Digest:
			// The published bytes win, because they are the ones that were signed and a
			// stale patch kept forever means running an old skill while believing you are
			// current. But "adopt again to keep it" was a lie: by the time anyone reads
			// it, their copy has already been moved and the file on disk is upstream's.
			// Say what happened and what it costs to get back.
			result.Lapsed = true
			result.Detail = "the publisher shipped a new version, so your copy was replaced " +
				"by theirs and kept in quarantine. Re-apply your change to the new version " +
				"and adopt that, if you still want it"
		default:
			result.Outcome = OutcomeAdapted
			result.Adapted, result.AdaptedSince = adoption.Reason, adoption.Since
			return result
		}
	}

	result.Outcome = OutcomeChanged
	if !options.Restore {
		return result
	}

	source, ok := pluginSource(manifest, options.Source, managed)
	if !ok {
		result.Outcome = OutcomeUnverifiable
		result.Detail = "no local copy of the signed bytes to restore from"
		return result
	}
	kept, err := RestoreVerified(
		installed, source, options.QuarantineRoot, managed.Name, options.Now, managed.Digest)
	if err != nil {
		result.Outcome, result.Detail = OutcomeUnverifiable, err.Error()
		return result
	}
	result.Outcome, result.Quarantine = OutcomeRestored, kept
	return result
}

// pluginSource finds the signed bytes for a published skill inside the catalog checkout.
//
// The catalog's own Path wins over the marketplace manifest, and is consulted even when there
// is no manifest at all. A catalog published with `catalog publish` names where each skill
// lives in the repository and has no marketplace.json to look it up in; a marketplace catalog
// leaves Path empty and is answered exactly as before.
func pluginSource(manifest *Manifest, repository string, managed catalog.Managed) (string, bool) {
	if repository == "" {
		return "", false
	}
	if managed.Path != "" {
		relative, ok := containedPath(managed.Path)
		if !ok {
			return "", false
		}
		return filepath.Join(repository, relative), true
	}
	if manifest == nil {
		return "", false
	}
	for _, entry := range manifest.Plugins {
		if entry.Name != managed.Name {
			continue
		}
		return entry.LocalPath(repository)
	}
	return "", false
}

// containedPath turns a slash-separated catalog path into a local one, refusing anything that
// would leave the directory it is joined to. The catalog is signed, so this is not the first
// line of defence — but a path from a document is still a path from a document, and one that
// escaped would read or replace a tree nobody published.
func containedPath(slashed string) (string, bool) {
	cleaned := path.Clean("/" + slashed)
	if cleaned == "/" {
		return "", false
	}
	return filepath.FromSlash(strings.TrimPrefix(cleaned, "/")), true
}
