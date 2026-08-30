package marketplace

import (
	"os"
	"sort"
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
	Marketplace string  `json:"marketplace"`
	Plugin      string  `json:"plugin"`
	Version     string  `json:"version"`
	Outcome     Outcome `json:"outcome"`
	Signed      string  `json:"signed,omitempty"`
	OnDisk      string  `json:"on_disk,omitempty"`
	Installed   string  `json:"installed_version,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Quarantine  string  `json:"quarantine,omitempty"`
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
}

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
	Now     time.Time
}

// Reconcile checks every plugin a signed marketplace claims, and optionally repairs it.
func Reconcile(snapshot *catalog.Snapshot, options Options) []Result {
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	manifest, _ := Load(options.Source)

	results := make([]Result, 0, len(snapshot.Skills))
	for _, managed := range snapshot.Skills {
		results = append(results, reconcileOne(snapshot, managed, manifest, options))
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Plugin < results[j].Plugin })
	return results
}

func reconcileOne(
	snapshot *catalog.Snapshot, managed catalog.Managed, manifest *Manifest, options Options,
) Result {
	result := Result{
		Marketplace: snapshot.Name, Plugin: managed.Name,
		Version: managed.Version, Signed: managed.Digest,
	}

	// Revocation is answered first and outranks everything, including a perfectly good
	// signature: a signature is a statement about the past and a revocation about now.
	if entry, revoked := snapshot.IsRevoked(managed.Digest); revoked {
		result.Outcome, result.Detail = OutcomeRevoked, entry.Reason
		return result
	}

	installed := InstalledPath(options.ClaudeHome, snapshot.Name, managed.Name, managed.Version)
	if _, err := os.Stat(installed); os.IsNotExist(err) {
		if others := InstalledVersions(options.ClaudeHome, snapshot.Name, managed.Name); len(others) > 0 {
			result.Outcome, result.Installed = OutcomeOtherVersion, others[0]
			return result
		}
		result.Outcome = OutcomeAbsent
		return result
	}

	digest, _, err := DigestPlugin(installed)
	if err != nil {
		result.Outcome, result.Detail = OutcomeUnverifiable, err.Error()
		return result
	}
	result.OnDisk = digest
	if digest == managed.Digest {
		result.Outcome = OutcomeVerified
		return result
	}

	// An adoption is a claim about exact bytes, not a licence to diverge. It applies only
	// while the local copy is still the copy that was adopted AND the catalog still
	// publishes the digest it was adopted away from. Anything else — someone editing the
	// file again, or upstream shipping a new version — falls back to being a difference
	// that needs a decision, which is the property that keeps this from being an off switch.
	if adoption, ok := options.Adopted.Find(snapshot.Name, managed.Name); ok {
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

	source, ok := pluginSource(manifest, options.Source, managed.Name)
	if !ok {
		result.Outcome = OutcomeUnverifiable
		result.Detail = "no local copy of the signed bytes to restore from"
		return result
	}
	kept, err := Restore(installed, source, options.QuarantineRoot, managed.Name, options.Now)
	if err != nil {
		result.Outcome, result.Detail = OutcomeUnverifiable, err.Error()
		return result
	}
	result.Outcome, result.Quarantine = OutcomeRestored, kept
	return result
}

// pluginSource finds the signed bytes for a plugin inside the marketplace checkout.
func pluginSource(manifest *Manifest, repository, name string) (string, bool) {
	if manifest == nil || repository == "" {
		return "", false
	}
	for _, entry := range manifest.Plugins {
		if entry.Name != name {
			continue
		}
		return entry.LocalPath(repository)
	}
	return "", false
}
