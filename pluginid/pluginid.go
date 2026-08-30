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

// Of returns the digest of a tree of bytes as received, and whether it ships dependency
// code the digest does not cover. Every file counts.
//
// This is the verifying side, and the default: an installed copy, an extracted archive, a
// tree materialised from a repository API. Nothing inside the directory may narrow what
// the identity covers — a `.git` planted in a tree would otherwise decide which of its own
// files are digested, which hands that choice to whoever wrote the tree.
//
// The rules it does apply are the ones signing uses, because they are the same call: files
// the client owns are excluded, so a source checkout and an installed copy stay
// comparable; the signature is never part of what it signs; symlinks are refused, because
// a link decides which bytes the identity covers and the answer must be in the tree itself.
func Of(directory string) (digest string, hasDependencies bool, err error) {
	return marketplace.DigestInstalled(directory)
}

// OfCheckout returns the digest of a publisher's working copy, where only git-tracked
// files count.
//
// A checkout is not what a consumer receives: build output, caches and local scratch live
// there and never reach a clone, so digesting the directory as it stands would sign a tree
// that exists on one machine and matches nobody's install. Asking git is safe here and
// only here, because the question is about the publisher's own machine before anything is
// signed. Never use this to check bytes somebody else produced.
func OfCheckout(directory string) (digest string, hasDependencies bool, err error) {
	return marketplace.DigestPlugin(directory)
}
