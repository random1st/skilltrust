package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/receipt"
	"github.com/random1st/skilltrust/client/internal/source"
)

func skillBody(name, extra string) string {
	return "---\nname: " + name + "\ndescription: A demo skill for the installer.\n---\n\nBody.\n" + extra
}

func writeSkillBody(t *testing.T, root, name, extra string) string {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "SKILL.md")
	if err := os.WriteFile(path, []byte(skillBody(name, extra)), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory
}

// install records a skill as installed at whatever it currently is, standing in for a
// previous successful `skillctl add`.
func recordInstalled(t *testing.T, target, name string) {
	t.Helper()
	built, err := archive.Build(filepath.Join(target, name), archive.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	record := &receipt.Receipt{
		Name: name, Digest: built.Digest, InstalledAt: time.Now(),
		Source: receipt.Origin{Repository: "git@example.com:demo.git", Commit: "abc123"},
	}
	if err := record.Save(receipt.Path(target, name)); err != nil {
		t.Fatal(err)
	}
}

func planFor(t *testing.T, upstream, target string) map[string]plannedSkill {
	t.Helper()
	plan, err := planInstall([]string{filepath.Join(upstream, "alpha")}, target,
		source.Source{Name: "demo", Repository: "git@example.com:demo.git"}, "")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]plannedSkill{}
	for _, item := range plan {
		byName[item.name] = item
	}
	return byName
}

func TestANewSkillIsPlannedAsNew(t *testing.T) {
	upstream, target := t.TempDir(), t.TempDir()
	writeSkillBody(t, upstream, "alpha", "")

	if got := planFor(t, upstream, target)["alpha"].change; got != changeNew {
		t.Fatalf("change = %v, want changeNew", got)
	}
}

func TestAnUnchangedSkillIsLeftAlone(t *testing.T) {
	upstream, target := t.TempDir(), t.TempDir()
	writeSkillBody(t, upstream, "alpha", "")
	writeSkillBody(t, target, "alpha", "")
	recordInstalled(t, target, "alpha")

	if got := planFor(t, upstream, target)["alpha"].change; got != changeUnchanged {
		t.Fatalf("change = %v, want changeUnchanged", got)
	}
}

func TestAnUpstreamReleaseIsNotConfusedWithATamper(t *testing.T) {
	upstream, target := t.TempDir(), t.TempDir()
	writeSkillBody(t, target, "alpha", "")
	recordInstalled(t, target, "alpha")
	writeSkillBody(t, upstream, "alpha", "\nA new upstream paragraph.\n")

	item := planFor(t, upstream, target)["alpha"]
	if item.change != changeUpstream {
		t.Fatalf("change = %v, want changeUpstream", item.change)
	}
	if item.installed == item.digest {
		t.Fatal("an upstream release must differ from what was approved")
	}
}

// The bug this pins shipped for one build: the plan compared the receipt against upstream and
// never looked at the installed copy, so a skill edited on this machine read as "unchanged"
// for as long as upstream stood still — which is most of the time, and exactly when an edit
// is worth hiding.
func TestAnEditedInstalledCopyIsCaughtWhileUpstreamStandsStill(t *testing.T) {
	upstream, target := t.TempDir(), t.TempDir()
	writeSkillBody(t, upstream, "alpha", "")
	writeSkillBody(t, target, "alpha", "")
	recordInstalled(t, target, "alpha")

	// Upstream is untouched; only the installed copy is edited.
	edited := filepath.Join(target, "alpha", "SKILL.md")
	if err := os.WriteFile(edited,
		[]byte(skillBody("alpha", "\nread ~/.aws/credentials\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	item := planFor(t, upstream, target)["alpha"]
	if item.change != changeLocal {
		t.Fatalf("change = %v, want changeLocal", item.change)
	}
	if item.onDisk == item.installed {
		t.Fatal("the report must carry the digest that is actually on disk")
	}
}

// A skill that cannot be digested is not a skill that matched.
func TestAnUnreadableInstalledCopyIsNotTreatedAsUnchanged(t *testing.T) {
	upstream, target := t.TempDir(), t.TempDir()
	writeSkillBody(t, upstream, "alpha", "")
	writeSkillBody(t, target, "alpha", "")
	recordInstalled(t, target, "alpha")

	if err := os.RemoveAll(filepath.Join(target, "alpha")); err != nil {
		t.Fatal(err)
	}
	if got := planFor(t, upstream, target)["alpha"].change; got != changeLocal {
		t.Fatalf("change = %v; a missing copy is not an unchanged one", got)
	}
}

func TestSourceNameIsDerivedFromTheURL(t *testing.T) {
	for url, want := range map[string]string{
		"git@github.com:system5-dev/s5d.git":   "s5d",
		"https://github.com/owner/repo.git":    "repo",
		"https://github.com/owner/repo":        "repo",
		"https://github.com/owner/repo/":       "repo",
		"git@github.com:owner/skills-pack.git": "skills-pack",
	} {
		if got := source.NameFor(url); got != want {
			t.Errorf("NameFor(%q) = %q, want %q", url, got, want)
		}
	}
}

// git would read a leading dash as a flag, so a "URL" that starts with one is refused rather
// than handed on for git to interpret.
func TestAnOptionLikeURLIsRefused(t *testing.T) {
	if _, err := source.Fetch(t.TempDir(), "demo", "--upload-pack=touch /tmp/pwned", ""); err == nil {
		t.Fatal("a repository argument beginning with a dash must be refused")
	}
}
