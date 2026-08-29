package marketplace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnUnusableAdoptionsFileAdoptsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adopted.json")

	// A missing file is the normal case, not an error: most machines adopt nothing.
	if adoptions, err := LoadAdoptions(path); err != nil || len(adoptions.Entries) != 0 {
		t.Fatalf("a missing file must be an empty set, got %v %v", adoptions, err)
	}

	// A corrupt one must fail closed. The other direction would mean a damaged file
	// quietly reads as "accept every difference on this machine".
	os.WriteFile(path, []byte("{not json"), 0o600)
	if adoptions, err := LoadAdoptions(path); err == nil || len(adoptions.Entries) != 0 {
		t.Error("an unreadable file must adopt nothing and say so")
	}

	// An entry that cannot do its job is dropped rather than half-honoured: with no local
	// digest there is nothing to compare against, and with no reason there is no record.
	os.WriteFile(path, []byte(`{"adopted":[
		{"marketplace":"m","plugin":"no-reason","from":"sha256:a","local":"sha256:b","reason":"  "},
		{"marketplace":"m","plugin":"no-bytes","from":"sha256:a","reason":"because"},
		{"marketplace":"m","plugin":"good","from":"sha256:a","local":"sha256:b","reason":"ours"}]}`), 0o600)
	adoptions, err := LoadAdoptions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(adoptions.Entries) != 1 || adoptions.Entries[0].Plugin != "good" {
		t.Errorf("only a complete entry may be honoured, got %+v", adoptions.Entries)
	}
}

func TestRecordReplacesAndForgetRemoves(t *testing.T) {
	first := Adoption{Marketplace: "m", Plugin: "p", From: "sha256:a", Local: "sha256:b",
		Reason: "one", Since: time.Now()}
	set := Adoptions{}.Record(first)

	// Adopting twice must replace, not accumulate: two records for one plugin would leave
	// which bytes are approved depending on iteration order.
	set = set.Record(Adoption{Marketplace: "m", Plugin: "p", From: "sha256:a",
		Local: "sha256:c", Reason: "two"})
	if len(set.Entries) != 1 || set.Entries[0].Local != "sha256:c" {
		t.Fatalf("re-adopting must replace, got %+v", set.Entries)
	}

	if _, found := set.Forget("m", "missing"); found {
		t.Error("forgetting something not adopted must report that it was not there")
	}
	set, found := set.Forget("m", "p")
	if !found || len(set.Entries) != 0 {
		t.Error("forgetting must remove the record so the published copy returns")
	}
}

// An empty Claude home once meant the relative path ./plugins/cache, so a caller that
// forgot to default it looked in the working directory, found nothing, and reported every
// plugin as not installed. That is the worst shape a bug can take here: a wrong answer that
// reads exactly like a right one, on the command whose whole job is to answer correctly.
func TestAnEmptyClaudeHomeDoesNotSearchTheWorkingDirectory(t *testing.T) {
	root := CacheRoot("")
	if !filepath.IsAbs(root) {
		t.Fatalf("an unset home must not resolve to a relative path, got %q", root)
	}
	if root != CacheRoot(DefaultClaudeHome()) {
		t.Errorf("an unset home must mean the default one, got %q", root)
	}
	// An explicit home still wins, or every test that points at a temporary directory
	// would silently be reading the real machine instead.
	if got := CacheRoot("/tmp/somewhere"); got != filepath.Join("/tmp/somewhere", "plugins", "cache") {
		t.Errorf("an explicit home must be honoured, got %q", got)
	}
}
