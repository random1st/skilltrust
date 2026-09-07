package attest

import (
	"os"
	"path/filepath"
	"testing"
)

// A file sitting where the store directory should be is damage the caller must hear
// about. On Windows listing a regular file reports "not found", so without an explicit
// check the damaged store read as an empty one and every approval vanished silently.
func TestLoadStoreRefusesAFileWhereTheDirectoryShouldBe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attestations")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStore(path, NewTrustedKeys()); err == nil {
		t.Fatal("a file in place of the store was read as an empty store")
	}
}
