package marketplace

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/archive"
)

// ClientManagedRoots are entries Claude Code maintains inside an installed plugin directory,
// which therefore cannot be part of what the publisher signs.
//
// `.in_use` is a directory of session locks — one file per live session holding the plugin,
// named by process id. It carries no behaviour, so excluding it from the identity costs
// nothing; but it must survive a restore, because removing it would drop the locks of
// sessions currently using the plugin. That it is a directory rather than a file is why
// client-managed entries are treated as opaque and moved across whole.
//
// `node_modules` is different and the difference must not be glossed over: it is executable
// code, installed on the machine after the plugin was fetched, and excluding it means the
// signature does not cover it. A plugin that has one is reported as partially verified rather
// than verified, because saying "verified" about a tree whose dependencies nobody signed
// would be the exact overclaim this project exists to avoid. An organisation that wants full
// coverage vendors its dependencies.
var ClientManagedRoots = []string{".in_use", "node_modules", ".git"}

// SignatureFileName is the marketplace's own signature, which cannot be part of what it
// signs.
//
// This is the same chicken-and-egg as the per-skill attestation, one level up, and it bites
// on the most natural layout there is: a marketplace whose single plugin is the repository
// root. The signature is written into that root after the digest is taken, so a consumer
// cloning the repository digests a tree containing a file the publisher's digest never saw.
// The symptom is not a failed check but a restore that never converges — the plugin is put
// back, still mismatches, and is put back again every session, forever.
//
// It is excluded at the root of a digested plugin only. Deeper in a tree the same name is
// ordinary content, exactly as with the attestation.
const SignatureFileName = "catalog.dsse.json"

// excludedRoots are every entry left out of a plugin's identity.
func excludedRoots() []string {
	return append(append([]string{}, ClientManagedRoots...), SignatureFileName)
}

// PluginLimits bound a plugin tree, which is a different animal from a skill folder.
//
// The skill defaults assume instructions: a few files, a few kilobytes each. A plugin
// legitimately ships platform binaries — the first real marketplace this was pointed at
// carries a 9.5 MB executable — and that binary is precisely the code that runs, so
// excluding it would be the largest hole available. The limits are raised rather than
// removed, because their job is unchanged: a hostile directory must fail loudly instead of
// exhausting the machine. They are still low enough to matter, since the whole tree is read
// into memory to be digested.
func PluginLimits() archive.Limits {
	return archive.Limits{
		MaxFiles:        8192,
		MaxFileBytes:    64 << 20,
		MaxTotalBytes:   256 << 20,
		MaxArchiveBytes: 320 << 20,
	}
}

// DigestPlugin computes the identity of a plugin tree on the publishing side: what a
// checkout would ship, ignoring what the client owns.
//
// It consults git, so a publisher's local build scratch does not change a published
// identity. That makes it wrong for anything a consumer verifies — use DigestInstalled
// for an installed copy.
func DigestPlugin(directory string) (string, bool, error) {
	var keep func(string) bool
	if tracked := trackedFiles(directory); tracked != nil {
		keep = func(path string) bool { _, ok := tracked[path]; return ok }
	}
	built, err := archive.BuildFiltered(directory, PluginLimits(), keep, excludedRoots()...)
	if err != nil {
		return "", false, err
	}
	return built.Digest, hasDependencies(directory), nil
}

// DigestInstalled computes the identity of an installed copy: every file counts.
//
// The git filter above must never run here. An installed copy contains only what was
// shipped, so there is no scratch to ignore — and asking git means letting data inside the
// tree decide what the digest covers, which hands that choice to whoever wrote the tree.
// The attack is concrete: `git init && git add SKILL.md && git commit` inside an installed
// plugin, and every file that repo does not track vanishes from the identity, so bytes
// nobody signed verify as published, forever. The two digests still agree on a clean
// install, because a clone delivers exactly the tracked files.
func DigestInstalled(directory string) (string, bool, error) {
	built, err := archive.BuildFiltered(directory, PluginLimits(), nil, excludedRoots()...)
	if err != nil {
		return "", false, err
	}
	return built.Digest, hasDependencies(directory), nil
}

// Coverage is what signing a marketplace could and could not account for.
type Coverage struct {
	Signed      []catalog.Managed
	Unversioned []string
	Remote      map[string][]string // source kind -> plugin names
	Partial     []string            // signed, but with dependency code outside the signature
}

// Plan digests every plugin a marketplace repository owns and reports what it cannot sign.
//
// Refusing to sign a marketplace that re-exports third-party plugins would make the tool
// unusable on the catalogs organisations actually have; signing them silently would be a
// lie, because those bytes come from somewhere the publisher does not control and cannot
// vouch for. So they are excluded and named, and the count is printed rather than buried.
func Plan(repository string, manifest *Manifest) (*Coverage, error) {
	coverage := &Coverage{Remote: map[string][]string{}}

	for _, entry := range manifest.Plugins {
		directory, local := entry.LocalPath(repository)
		if !local {
			kind := entry.SourceKind()
			coverage.Remote[kind] = append(coverage.Remote[kind], entry.Name)
			continue
		}
		version := entry.ResolveVersion(repository)
		if version == "" {
			// Without a version the installed directory cannot be named, so a signature over
			// these bytes could never be checked against anything.
			coverage.Unversioned = append(coverage.Unversioned, entry.Name)
			continue
		}
		digest, dependencies, err := DigestPlugin(directory)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name, err)
		}
		if dependencies {
			coverage.Partial = append(coverage.Partial, entry.Name)
		}
		coverage.Signed = append(coverage.Signed, catalog.Managed{
			Name: entry.Name, Digest: digest, Version: version,
		})
	}

	sort.Slice(coverage.Signed, func(i, j int) bool {
		return coverage.Signed[i].Name < coverage.Signed[j].Name
	})
	sort.Strings(coverage.Unversioned)
	sort.Strings(coverage.Partial)
	for kind := range coverage.Remote {
		sort.Strings(coverage.Remote[kind])
	}
	return coverage, nil
}

// trackedFiles returns the paths git would ship from a directory, or nil when the directory
// is not inside a repository.
//
// A publisher's checkout is not what a consumer receives: build output, caches and local
// scratch live there and never reach a clone. The first real marketplace this was pointed at
// carried 280 MB of Rust build artifacts that git ignores and the plugin cache does not have,
// so digesting the directory as it stands would have signed a tree that exists on exactly one
// machine and matches nobody's install.
func trackedFiles(directory string) map[string]struct{} {
	command := exec.Command("git", "-C", directory, "ls-files", "-z", "--cached", "--")
	output, err := command.Output()
	if err != nil {
		return nil
	}
	tracked := map[string]struct{}{}
	for _, name := range strings.Split(string(output), "\x00") {
		if name != "" {
			tracked[name] = struct{}{}
		}
	}
	if len(tracked) == 0 {
		return nil
	}
	return tracked
}
