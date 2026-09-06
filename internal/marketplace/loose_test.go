package marketplace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/catalog"
)

// writeSkill puts a loose skill directory on disk and returns its digest — the identity a
// consumer computes about a directory, which is the only identity a client with no
// marketplace and no versions can have.
func writeSkill(t *testing.T, directory, body string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _, err := DigestInstalled(directory)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// The layouts a real host has. A single-profile host keeps skills at <home>/skills; a host
// running several keeps a set per profile and may keep the machine-wide root as well. A
// locator that knew only the first would report on one directory and stay quiet about the
// others, which on a fleet host is most of what is installed.
func TestLooseSkillsFindsEveryRootAndLabelsThemByProfile(t *testing.T) {
	home := t.TempDir()
	machine := filepath.Join(home, "skills")
	operator := filepath.Join(home, "profiles", "operator", "skills")
	analyst := filepath.Join(home, "profiles", "analyst", "skills")
	for _, root := range []string{machine, operator, analyst} {
		writeSkill(t, filepath.Join(root, "aws-readonly"), "read only\n")
	}

	copies := LooseSkills([]SkillRoot{
		{Path: machine},
		{Path: operator, Label: "operator"},
		{Path: analyst, Label: "analyst"},
		// A profile this machine does not run. Absent roots contribute nothing rather than
		// a finding: not every host runs every profile.
		{Path: filepath.Join(home, "profiles", "auditor", "skills"), Label: "auditor"},
	})(catalog.Managed{Name: "aws-readonly"})

	if len(copies) != 3 {
		t.Fatalf("copies = %d, want the three roots that exist: %+v", len(copies), copies)
	}
	labels := map[string]string{}
	for _, copy := range copies {
		labels[copy.Label] = copy.Path
	}
	if labels[""] != filepath.Join(machine, "aws-readonly") {
		t.Errorf("the machine root must carry no label, got %+v", copies)
	}
	if labels["operator"] != filepath.Join(operator, "aws-readonly") ||
		labels["analyst"] != filepath.Join(analyst, "aws-readonly") {
		t.Errorf("each profile must be labelled with its own name, got %+v", copies)
	}
}

// A single-profile host is the ordinary case and must need no profiles directory at all.
func TestLooseSkillsOnASingleProfileHost(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	writeSkill(t, filepath.Join(root, "aws-readonly"), "read only\n")

	copies := LooseSkills([]SkillRoot{{Path: root}})(catalog.Managed{Name: "aws-readonly"})
	if len(copies) != 1 || copies[0].Label != "" ||
		copies[0].Path != filepath.Join(root, "aws-readonly") {
		t.Fatalf("copies = %+v", copies)
	}
}

// Where a skill sits in the publisher's repository is where it sits under the client's skills
// root. The repository's own skills/ directory is what the client's root already stands for,
// so it is the one element that is dropped — anything else would look for a nesting the
// client does not have and report a skill nobody installed.
func TestLooseSkillsMirrorsTheCatalogPathUnderTheRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	nested := filepath.Join(root, "analytics", "source-validation")
	writeSkill(t, nested, "check the sources\n")
	writeSkill(t, filepath.Join(root, "flat"), "flat\n")

	cases := map[string]struct {
		managed catalog.Managed
		want    string
	}{
		"nested under the repository's skills directory": {
			catalog.Managed{
				Name: "source-validation",
				Path: "skills/analytics/source-validation",
			}, nested,
		},
		"a path with no nesting": {
			catalog.Managed{Name: "flat", Path: "skills/flat"}, filepath.Join(root, "flat"),
		},
		"no path at all is the skill's own name": {
			catalog.Managed{Name: "flat"}, filepath.Join(root, "flat"),
		},
	}
	for name, one := range cases {
		t.Run(name, func(t *testing.T) {
			copies := LooseSkills([]SkillRoot{{Path: root}})(one.managed)
			if len(copies) != 1 || copies[0].Path != one.want {
				t.Fatalf("copies = %+v, want %s", copies, one.want)
			}
		})
	}

	// A skill the catalog publishes and this machine did not take is absent, not a copy at
	// a path that happens not to exist.
	if copies := LooseSkills([]SkillRoot{{Path: root}})(
		catalog.Managed{Name: "never-installed"}); len(copies) != 0 {
		t.Errorf("a skill nobody installed produced copies: %+v", copies)
	}
}

// A path from a signed document is still a path from a document. One that climbed out of the
// skills root would read — and with --restore, replace — a tree nobody published.
func TestLooseSkillsRefusesAPathThatLeavesTheRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "skills")
	writeSkill(t, filepath.Join(root, "ok"), "ok\n")
	writeSkill(t, filepath.Join(base, "elsewhere"), "not published here\n")

	for _, escape := range []string{"../elsewhere", "skills/../../elsewhere", "/etc"} {
		copies := LooseSkills([]SkillRoot{{Path: root}})(
			catalog.Managed{Name: "ok", Path: escape})
		for _, copy := range copies {
			if !strings.HasPrefix(copy.Path, root) {
				t.Errorf("%q reached outside the skills root: %s", escape, copy.Path)
			}
		}
	}
}

func looseSnapshot(name string, skills ...catalog.Managed) *catalog.Snapshot {
	return &catalog.Snapshot{Name: name, Skills: skills}
}

// The whole point of the adapter: a byte-identical copy of a published skill verifies as
// published, with no marketplace, no version and no cache anywhere in the path.
func TestALooseCopyOfThePublishedBytesVerifies(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	digest := writeSkill(t, filepath.Join(root, "aws-readonly"), "read only\n")

	results := Reconcile(
		looseSnapshot("acme", catalog.Managed{Name: "aws-readonly", Digest: digest}),
		Options{Locate: LooseSkills([]SkillRoot{{Path: root}})})

	if len(results) != 1 || results[0].Outcome != OutcomeVerified {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Copy != "" {
		t.Errorf("a client with one copy must not invent a name for it: %q", results[0].Copy)
	}
}

// An edit nobody accounted for is a finding, and with restoring on it is put back and the
// bytes that were there are kept. Losing the replaced copy would destroy the evidence in the
// one case that is an incident.
func TestALooseCopyChangedHereIsRestoredAndTheOldOneKept(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	repository := t.TempDir()
	published := "---\nname: aws-readonly\n---\nread only\n"
	digest := writeSkill(t, filepath.Join(repository, "skills", "aws-readonly"), published)
	writeSkill(t, filepath.Join(root, "aws-readonly"), "---\nname: aws-readonly\n---\nedited\n")

	managed := catalog.Managed{
		Name: "aws-readonly", Digest: digest, Path: "skills/aws-readonly",
	}
	quarantineRoot := filepath.Join(t.TempDir(), "quarantine")

	// Reporting first: nothing is changed and the difference is named.
	reported := Reconcile(looseSnapshot("acme", managed), Options{
		Locate: LooseSkills([]SkillRoot{{Path: root}}), Source: repository,
	})
	if len(reported) != 1 || reported[0].Outcome != OutcomeChanged {
		t.Fatalf("report-only results = %+v", reported)
	}

	results := Reconcile(looseSnapshot("acme", managed), Options{
		Locate: LooseSkills([]SkillRoot{{Path: root}}),
		Source: repository, QuarantineRoot: quarantineRoot, Restore: true,
	})
	if len(results) != 1 || results[0].Outcome != OutcomeRestored {
		t.Fatalf("results = %+v", results)
	}
	body, err := os.ReadFile(filepath.Join(root, "aws-readonly", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != published {
		t.Fatalf("the published bytes were not put back: %q", body)
	}
	if results[0].Quarantine == "" {
		t.Fatal("the copy that was replaced must be kept somewhere reachable")
	}
	kept, err := os.ReadFile(filepath.Join(results[0].Quarantine, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kept), "edited") {
		t.Fatalf("the quarantined copy is not the one that was replaced: %q", kept)
	}
}

// Two profiles, one edited and one intact, are two answers about two files. Reporting them
// under one name would leave a person unable to tell which copy to look at — and would make
// the intact one look like the finding half the time.
func TestEachProfileIsReportedSeparately(t *testing.T) {
	home := t.TempDir()
	operator := filepath.Join(home, "profiles", "operator", "skills")
	analyst := filepath.Join(home, "profiles", "analyst", "skills")
	digest := writeSkill(t, filepath.Join(operator, "aws-readonly"), "read only\n")
	writeSkill(t, filepath.Join(analyst, "aws-readonly"), "read only, plus our region\n")

	results := Reconcile(
		looseSnapshot("acme", catalog.Managed{Name: "aws-readonly", Digest: digest}),
		Options{Locate: LooseSkills([]SkillRoot{
			{Path: analyst, Label: "analyst"},
			{Path: operator, Label: "operator"},
		})})

	if len(results) != 2 {
		t.Fatalf("results = %+v, want one per profile", results)
	}
	byCopy := map[string]Result{}
	for _, result := range results {
		byCopy[result.Copy] = result
	}
	if byCopy["operator"].Outcome != OutcomeVerified {
		t.Errorf("the untouched profile must verify, got %+v", byCopy["operator"])
	}
	if byCopy["analyst"].Outcome != OutcomeChanged {
		t.Errorf("the edited profile must be a finding, got %+v", byCopy["analyst"])
	}
	if results[0].Copy == results[1].Copy {
		t.Fatal("two copies of one skill must be distinguishable in a report")
	}
}

// An adoption naming one copy must not quiet another. Two profiles edited differently, each
// on purpose, is the ordinary state of a host that runs several agents — and a record for one
// of them saying nothing about the other is what keeps adopting from being an off switch.
func TestAnAdoptionAppliesOnlyToTheCopyItNames(t *testing.T) {
	home := t.TempDir()
	operator := filepath.Join(home, "profiles", "operator", "skills")
	analyst := filepath.Join(home, "profiles", "analyst", "skills")
	mine := writeSkill(t, filepath.Join(operator, "aws-readonly"), "our region\n")
	writeSkill(t, filepath.Join(analyst, "aws-readonly"), "a different edit\n")

	adopted := Adoptions{Entries: []Adoption{{
		Marketplace: "acme", Plugin: "aws-readonly", Copy: "operator",
		From: "sha256:published", Local: mine, Reason: "our region", Since: time.Now(),
	}}}

	results := Reconcile(
		looseSnapshot("acme", catalog.Managed{Name: "aws-readonly", Digest: "sha256:published"}),
		Options{
			Adopted: adopted,
			Locate: LooseSkills([]SkillRoot{
				{Path: operator, Label: "operator"}, {Path: analyst, Label: "analyst"},
			}),
		})

	byCopy := map[string]Result{}
	for _, result := range results {
		byCopy[result.Copy] = result
	}
	if byCopy["operator"].Outcome != OutcomeAdapted {
		t.Errorf("the adopted copy must be kept, got %+v", byCopy["operator"])
	}
	if byCopy["analyst"].Outcome != OutcomeChanged {
		t.Errorf("an adoption of another profile's copy must not cover this one, got %+v",
			byCopy["analyst"])
	}
}

// A record naming no copy is what every person who has ever adopted anything wrote, and what
// a client with a single copy still writes. It must keep covering that copy exactly as it did
// before copies had names at all.
func TestARecordNamingNoCopyCoversTheOneCopyThereIs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	mine := writeSkill(t, filepath.Join(root, "aws-readonly"), "ours\n")

	adopted := Adoptions{}.Record(Adoption{
		Marketplace: "acme", Plugin: "aws-readonly",
		From: "sha256:published", Local: mine, Reason: "ours", Since: time.Now(),
	})
	results := Reconcile(
		looseSnapshot("acme", catalog.Managed{Name: "aws-readonly", Digest: "sha256:published"}),
		Options{Adopted: adopted, Locate: LooseSkills([]SkillRoot{{Path: root}})})

	if len(results) != 1 || results[0].Outcome != OutcomeAdapted {
		t.Fatalf("results = %+v", results)
	}

	// And the same record read by name, which is how every existing caller asks.
	if _, found := adopted.Find("acme", "aws-readonly"); !found {
		t.Error("a copy-less record must still be found by marketplace and plugin alone")
	}
}
