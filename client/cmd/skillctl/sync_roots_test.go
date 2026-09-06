package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/random1st/skilltrust/attest"
)

func TestSyncOptionalLooseRootsDistinguishAbsenceFromErrors(t *testing.T) {
	base := t.TempDir()
	if roots, err := optionalSkillRoots([]string{base}); err != nil || len(roots) != 0 {
		t.Fatalf("a plugin-only installation requires no loose skills: %v, %v", roots, err)
	}
	root := filepath.Join(base, ".agents", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := optionalSkillRoots([]string{base}); err == nil {
		t.Fatal("a broken skills directory was treated as absent")
	}
}

func TestSyncDoesNotHideLooseDirectoryReadErrors(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, _, code := verifySkillRootsReporting(attest.NewTrustedKeys(), true, []string{root})
	if code == exitClean || summary.Errors == 0 || summary.Complete {
		t.Fatalf("an unreadable root looked checked: %+v, exit %d", summary, code)
	}
}
