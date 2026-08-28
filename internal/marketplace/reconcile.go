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
)

// Settled reports whether an outcome needs no attention and no words.
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
