package marketplace

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	digest, _, dependencies, err := digestPublished(directory)
	return digest, dependencies, err
}

// digestPublished also reports the tracked paths the archive does not cover, because those
// are precisely the bytes a clone will deliver and this digest will not describe.
func digestPublished(directory string) (string, []string, bool, error) {
	var keep func(string) bool
	tracked := trackedFiles(directory)
	if tracked != nil {
		keep = func(path string) bool { _, ok := tracked[path]; return ok }
	}
	built, err := archive.BuildFiltered(directory, PluginLimits(), keep, excludedRoots()...)
	if err != nil {
		return "", nil, false, err
	}
	if missing := absentFromDisk(directory, tracked, built); len(missing) > 0 {
		// Refused rather than reported. Every one of these is a file a clone hands the
		// consumer and this signature does not mention, so the digest would be one nobody
		// but this machine can reproduce and every install would read as tampering. It is
		// a working-tree accident — a file moved or deleted without committing — and the
		// publisher is standing right there and can fix it.
		return "", nil, false, fmt.Errorf(
			"%d tracked file(s) are missing from the working tree, so this digest would "+
				"not match what a clone delivers: %s", len(missing), strings.Join(missing, ", "))
	}
	return built.Digest, gitlinks(directory, tracked), hasDependencies(directory), nil
}

// absentFromDisk is tracked paths that produced no archive member and are not directories.
//
// A gitlink is a tracked path that exists as a directory, so it is excluded here and
// reported separately: its contents are a different repository's to vouch for.
func absentFromDisk(directory string, tracked map[string]struct{}, built *archive.Archive) []string {
	if tracked == nil {
		return nil
	}
	covered := make(map[string]struct{}, len(built.Files))
	for _, file := range built.Files {
		covered[file.Path] = struct{}{}
	}
	var missing []string
	for name := range tracked {
		if _, ok := covered[name]; ok {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, filepath.FromSlash(name)))
		if err == nil && info.IsDir() {
			continue // a directory, or a submodule; neither is a missing file
		}
		if excludedName(name) {
			continue // client-managed or the signature itself, deliberately outside
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return missing
}

// gitlinks names submodules inside a plugin. git tracks the pointer, never the contents, so
// nothing under one is inside the signature — and a recursive clone still delivers those
// bytes. Reported rather than refused: they are somebody else's to vouch for, which is the
// same reason vendored dependencies are reported instead of signed.
func gitlinks(directory string, tracked map[string]struct{}) []string {
	var found []string
	for name := range tracked {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if info, err := os.Lstat(path); err == nil && info.IsDir() {
			if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
				found = append(found, name)
			}
		}
	}
	sort.Strings(found)
	return found
}

// excludedName reports whether a path lies under an entry the identity never covers.
func excludedName(name string) bool {
	head, _, _ := strings.Cut(name, "/")
	for _, excluded := range excludedRoots() {
		if head == excluded {
			return true
		}
	}
	return false
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
	// Submodules are plugin-relative paths whose contents git tracks in another repository
	// and this signature therefore does not cover, even though a recursive clone delivers
	// them. Named individually because "partial" alone does not tell a publisher where.
	Submodules []string
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
		digest, submodules, dependencies, err := digestPublished(directory)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name, err)
		}
		if dependencies || len(submodules) > 0 {
			coverage.Partial = append(coverage.Partial, entry.Name)
		}
		for _, submodule := range submodules {
			coverage.Submodules = append(coverage.Submodules, entry.Name+"/"+submodule)
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
	sort.Strings(coverage.Submodules)
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
		if name == "" {
			continue
		}
		tracked[name] = struct{}{}
		// Every directory on the way to a tracked file is tracked too, as far as this
		// filter is concerned. The walk asks about directories before it descends, and a
		// set of files alone would answer "no" to all of them and collect nothing. Naming
		// the parents is also what lets the walk skip a subtree whole, instead of
		// descending through build output to discard it a file at a time.
		for parent := path.Dir(name); parent != "." && parent != "/"; parent = path.Dir(parent) {
			tracked[parent] = struct{}{}
		}
	}
	if len(tracked) == 0 {
		return nil
	}
	return tracked
}
