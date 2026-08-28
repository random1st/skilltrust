// Package pluginid computes the identity of a plugin tree: the digest a catalog records
// and a consumer recomputes.
//
// It exists so that identity has exactly one implementation. A verifier that computes the
// digest its own way — a hosted service checking what a publisher uploaded, a third party
// auditing a catalog — has re-derived a canonicalisation, and the day the two disagree the
// disagreement looks like tampering. Both sides call this.
package pluginid

import (
	"github.com/random1st/skilltrust/internal/marketplace"
)

// Of returns the digest of the plugin rooted at directory, and whether that plugin ships
// dependency code the digest does not cover.
//
// The rules are the ones signing uses, because they are the same call: files the client
// owns are excluded, so a source checkout and an installed copy are comparable; the
// signature is never part of what it signs; symlinks are refused, because a link decides
// which bytes the identity covers and the answer must be in the tree itself.
//
// Inside a git checkout only tracked files count, which keeps a stray local build artefact
// from changing a published identity. Outside one — an extracted archive, a temporary
// directory — every file counts, since there is nothing to ask.
func Of(directory string) (digest string, hasDependencies bool, err error) {
	return marketplace.DigestPlugin(directory)
}
