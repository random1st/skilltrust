package receipt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	approvedAt := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	record := &Receipt{
		Name: "demo", Digest: "sha256:aa", Source: Origin{Bundle: "demo.tar"}, InstalledAt: time.Now(),
		Approval: &Approval{By: "reviewer", At: approvedAt, KeyID: "sha256:bb"},
	}
	if err := record.Save(Path(root, "demo")); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(Path(root, "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "demo" || loaded.Digest != "sha256:aa" {
		t.Fatalf("receipt = %+v", loaded)
	}
	if loaded.Approval == nil || loaded.Approval.By != "reviewer" {
		t.Fatalf("approval = %+v", loaded.Approval)
	}
}

// An unapproved install must stay distinguishable from an approved one forever after, so
// the absence of an approval is recorded as absence rather than filled in.
func TestUnapprovedInstallHasNoApproval(t *testing.T) {
	root := t.TempDir()
	record := &Receipt{Name: "demo", Digest: "sha256:aa", Source: Origin{Bundle: "demo.tar"}, InstalledAt: time.Now()}
	if err := record.Save(Path(root, "demo")); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(Path(root, "demo"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Approval != nil {
		t.Fatalf("approval = %+v, want nil", loaded.Approval)
	}
}

func TestLoadAllIsSortedAndToleratesAnAbsentDirectory(t *testing.T) {
	root := t.TempDir()

	records, err := LoadAll(root)
	if err != nil || records != nil {
		t.Fatalf("an unmanaged tree must read as empty: %v %v", records, err)
	}

	for _, name := range []string{"zeta", "alpha"} {
		record := &Receipt{Name: name, Digest: "sha256:aa", Source: Origin{Bundle: "x"}, InstalledAt: time.Now()}
		if err := record.Save(Path(root, name)); err != nil {
			t.Fatal(err)
		}
	}

	records, err = LoadAll(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Name != "alpha" || records[1].Name != "zeta" {
		t.Fatalf("records = %+v", records)
	}
}

// Skipping an unreadable receipt would report a managed skill as unmanaged, which is the
// wrong direction to be wrong in.
func TestUnreadableReceiptIsAnError(t *testing.T) {
	root := t.TempDir()
	path := Path(root, "demo")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadAll(root); err == nil {
		t.Fatal("an unreadable receipt must not be skipped")
	}
}

func TestFutureReceiptVersionIsRefused(t *testing.T) {
	root := t.TempDir()
	path := Path(root, "demo")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":999,"name":"demo"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a newer receipt format must be refused, not partially read")
	}
}
