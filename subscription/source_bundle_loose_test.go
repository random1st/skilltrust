package subscription

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/random1st/skilltrust/internal/archive"
	"github.com/random1st/skilltrust/internal/marketplace"
)

// A repository of skills under skills/ is what `catalog publish` signs and what every
// loose-skills client installs. Team delivery used to require a native marketplace, so
// such a catalog could be signed, verified and followed — and never handed over.
func looseSourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sourceFile(t, root, "skills/pregmate-map/SKILL.md", "# Where things live\n", 0o644)
	sourceFile(t, root, "skills/pregmate-map/references/map.md", "Redash lives here.\n", 0o644)
	sourceFile(t, root, "skills/analytics/late-refunds/SKILL.md", "# Late refunds\n", 0o644)
	sourceFile(t, root, "skills/analytics/late-refunds/run.sh", "#!/bin/sh\nexit 0\n", 0o755)
	sourceFile(t, root, "README.md", "UNRELATED-ROOT-CONTENT-MUST-NOT-TRAVEL\n", 0o644)
	sourceFile(t, root, "catalog.pub", "PUBLISHER-KEY-MUST-NOT-TRAVEL\n", 0o644)
	sourceFile(t, root, ".git/source-fixture", "GIT-DATA-MUST-NOT-TRAVEL\n", 0o600)
	return root
}

func TestSourceBundleDeliversASkillsRepositoryWithoutANativeManifest(t *testing.T) {
	root := looseSourceFixture(t)
	before := sourceSnapshot(t, root)
	payload, digest, err := BuildSource(root)
	if err != nil {
		t.Fatal(err)
	}
	canonical := gunzipSource(t, payload)
	if archive.DigestOf(canonical) != digest || len(payload) > MaxSourceBytes {
		t.Fatal("wire payload does not carry its canonical archive identity")
	}
	for _, secret := range []string{"UNRELATED-ROOT-CONTENT", "PUBLISHER-KEY", "GIT-DATA"} {
		if bytes.Contains(canonical, []byte(secret)) {
			t.Fatalf("source bundle disclosed %s", secret)
		}
	}
	destination := filepath.Join(t.TempDir(), "team skills")
	if err := ExtractSource(payload, destination, digest); err != nil {
		t.Fatal(err)
	}
	after := sourceSnapshot(t, destination)
	for _, member := range []string{
		"skills/pregmate-map/SKILL.md",
		"skills/pregmate-map/references/map.md",
		"skills/analytics/late-refunds/SKILL.md",
		"skills/analytics/late-refunds/run.sh",
	} {
		if after[member] != before[member] {
			t.Fatalf("source bytes or mode changed for %s", member)
		}
	}
	if len(after) != 4 {
		t.Fatalf("delivery carried files outside the published skills: %v", after)
	}
	if _, err := os.Lstat(filepath.Join(destination, marketplace.ManifestPath)); !os.IsNotExist(err) {
		t.Fatal("delivery invented a native manifest the publisher never signed")
	}
	if !reflect.DeepEqual(before, sourceSnapshot(t, root)) {
		t.Fatal("building or extracting modified the original source")
	}
}

func TestSourceBundleRefusesARepositoryThatPublishesNeitherShape(t *testing.T) {
	root := t.TempDir()
	sourceFile(t, root, "README.md", "Nothing published here.\n", 0o644)
	if _, _, err := BuildSource(root); err == nil {
		t.Fatal("a repository with no marketplace and no skills was delivered anyway")
	}
	// A skills directory holding no SKILL.md is the same emptiness by another route.
	sourceFile(t, root, "skills/notes/README.md", "Not a skill.\n", 0o644)
	if _, _, err := BuildSource(root); err == nil {
		t.Fatal("a skills directory without a single skill was delivered anyway")
	}
}

// The omission rules protect the same thing in both shapes: whatever is published must
// arrive whole. Only the manifest check is native-specific.
func TestValidateSourceReadCoversSkillsWithoutRequiringAManifest(t *testing.T) {
	root := looseSourceFixture(t)
	if err := ValidateSourceRead(root, []string{"README.md", "docs/design.md"}); err != nil {
		t.Fatalf("unrelated omissions blocked delivery: %v", err)
	}
	if err := ValidateSourceRead(root, []string{"skills/pregmate-map/references/map.md"}); err == nil {
		t.Fatal("an omission inside a published skill was accepted")
	}
	if err := ValidateSourceRead(root, []string{marketplace.ManifestPath}); err != nil {
		t.Fatalf("a skills repository was held to a manifest it never had: %v", err)
	}
}
