package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/archive"
)

// A skills repository carries no native manifest, so the plugin coverage check could
// never verify one — the shape `catalog publish` signs was refused on arrival.
func skillsSourceFixture(t *testing.T) (string, *catalog.Snapshot) {
	t.Helper()
	root := t.TempDir()
	write := func(member, body string) {
		filename := filepath.Join(root, filepath.FromSlash(member))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("skills/pregmate-map/SKILL.md", "---\nname: pregmate-map\n---\n# Where things live\n")
	write("skills/analytics/late-refunds/SKILL.md", "---\nname: late-refunds\n---\n# Late refunds\n")
	snapshot := &catalog.Snapshot{Version: catalog.SnapshotVersion, Name: "hermes-skills", Sequence: 1}
	for _, pair := range [][2]string{
		{"pregmate-map", "skills/pregmate-map"},
		{"late-refunds", "skills/analytics/late-refunds"},
	} {
		built, err := archive.Build(filepath.Join(root, filepath.FromSlash(pair[1])), archive.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Skills = append(snapshot.Skills, catalog.Managed{Name: pair[0], Digest: built.Digest, Path: pair[1]})
	}
	return root, snapshot
}

func TestVerifyPublicSubscriptionAcceptsASkillsRepositoryWithoutAManifest(t *testing.T) {
	root, snapshot := skillsSourceFixture(t)
	count, uncovered, err := verifyPublicSubscriptionSource(root, snapshot)
	if err != nil || count != 2 || uncovered != 0 {
		t.Fatalf("a signed skills repository was refused: count=%d uncovered=%d err=%v", count, uncovered, err)
	}
}

func TestVerifyPublicSubscriptionHoldsSkillsToTheirSignedBytesAndSet(t *testing.T) {
	t.Run("changed bytes", func(t *testing.T) {
		root, snapshot := skillsSourceFixture(t)
		if err := os.WriteFile(filepath.Join(root, "skills/pregmate-map/SKILL.md"), []byte("# Rewritten\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifyPublicSubscriptionSource(root, snapshot); err == nil {
			t.Fatal("a rewritten skill passed as its signed content")
		}
	})
	t.Run("missing skill", func(t *testing.T) {
		root, snapshot := skillsSourceFixture(t)
		if err := os.RemoveAll(filepath.Join(root, "skills/analytics")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifyPublicSubscriptionSource(root, snapshot); err == nil {
			t.Fatal("a catalog naming an absent skill was accepted")
		}
	})
	t.Run("unpublished extra", func(t *testing.T) {
		root, snapshot := skillsSourceFixture(t)
		extra := filepath.Join(root, "skills/smuggled")
		if err := os.MkdirAll(extra, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(extra, "SKILL.md"), []byte("# Never signed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifyPublicSubscriptionSource(root, snapshot); err == nil {
			t.Fatal("a skill the catalog never published arrived unnoticed")
		}
	})
}
