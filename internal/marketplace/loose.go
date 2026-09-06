package marketplace

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/random1st/skilltrust/catalog"
)

// SkillRoot is one directory a client reads loose skills from, and the name its copies are
// reported under.
//
// Label is empty for a client's single machine-wide root and is the profile name when the
// client keeps a set of skills per profile. It is not a path: what a person needs in a report
// is "operator", not the seventh element of a directory tree they already know.
type SkillRoot struct {
	Path  string
	Label string
}

// LooseSkills locates copies of a published skill in directories a client reads them from
// directly — no marketplace, no cache, no version.
//
// A copy is identified by the catalog entry's own layout: where the skill sits in the
// publisher's repository is where it sits under the client's skills root. That is the only
// identity available here, because nothing on disk records which catalog a loose directory
// came from — so the digest does the rest, and a directory that is not the published bytes is
// reported as changed rather than assumed to be someone else's skill of the same name.
//
// A root that does not exist contributes nothing rather than an absence: the machine simply
// does not have that profile, and reporting it would put a finding on every machine that
// happens to run one profile instead of three.
func LooseSkills(roots []SkillRoot) Locator {
	return func(managed catalog.Managed) []InstalledCopy {
		relative, ok := looseSkillPath(managed)
		if !ok {
			return nil
		}
		var copies []InstalledCopy
		for _, root := range roots {
			if root.Path == "" {
				continue
			}
			directory := filepath.Join(root.Path, relative)
			if info, err := os.Stat(directory); err != nil || !info.IsDir() {
				continue
			}
			copies = append(copies, InstalledCopy{Path: directory, Label: root.Label})
		}
		return copies
	}
}

// looseSkillPath is where a published skill sits under a client's skills root.
//
// The catalog's Path is relative to the publisher's repository, where skills conventionally
// live under a skills/ directory that the client's own skills root already stands for. So
// that one leading element is dropped and the rest is kept: a catalog path of
// skills/analytics/source-validation is analytics/source-validation on the machine, which is
// the nesting the client actually reads. A catalog that names no path is the flat case, and
// the skill's name is the directory.
func looseSkillPath(managed catalog.Managed) (string, bool) {
	slashed := managed.Path
	if slashed == "" {
		slashed = managed.Name
	}
	cleaned := path.Clean("/" + slashed)
	trimmed := strings.TrimPrefix(cleaned, "/")
	if managed.Path != "" {
		if rest, isSkills := strings.CutPrefix(trimmed, "skills/"); isSkills {
			trimmed = rest
		}
	}
	if trimmed == "" || trimmed == "." {
		return "", false
	}
	return filepath.FromSlash(trimmed), true
}
