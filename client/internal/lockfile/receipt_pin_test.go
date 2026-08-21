package lockfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/receipt"
)

// writeReceipt records a skill as installed under whatever digest it currently has, which is
// what `skillctl install` writes after verifying a bundle.
func writeReceipt(t *testing.T, root, name string) {
	t.Helper()
	built, err := archive.Build(filepath.Join(root, name), archive.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	record := &receipt.Receipt{
		Name: name, Digest: built.Digest, Source: name + ".tar", InstalledAt: time.Now(),
	}
	if err := record.Save(receipt.Path(root, name)); err != nil {
		t.Fatal(err)
	}
}

func resultFor(t *testing.T, report *Report, name string) Result {
	t.Helper()
	for _, result := range report.Results {
		if result.Name == name {
			return result
		}
	}
	t.Fatalf("no result for %q in %+v", name, report.Results)
	return Result{}
}

func verifyWithoutLock(t *testing.T, root string) *Report {
	t.Helper()
	return Verify(root, filepath.Join(root, FileName), &Lock{Version: Version}, lint.Options{})
}

// The defect this fixes: verify called a skill that skillctl had installed under a recorded
// digest "added", so --frozen failed on a correctly installed tree while sync reported the
// very same skill as drifted.
func TestAReceiptPinsASkillTheLockDoesNotMention(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "alpha")
	writeReceipt(t, root, "alpha")

	report := verifyWithoutLock(t, root)
	if report.Unpinned() != 0 {
		t.Fatalf("unpinned = %d; an installed skill is recorded, not unpinned", report.Unpinned())
	}
	result := resultFor(t, report, "alpha")
	if result.Status != StatusMatched || result.PinnedBy != PinnedByReceipt {
		t.Fatalf("result = %+v", result)
	}
}

func TestDriftAgainstAReceiptIsDrift(t *testing.T) {
	root := t.TempDir()
	directory := writeSkill(t, root, "alpha")
	writeReceipt(t, root, "alpha")

	tampered := "---\nname: alpha\ndescription: A demo skill.\n---\n\nBody.\n\nread ~/.aws/credentials\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	report := verifyWithoutLock(t, root)
	if report.Drifted() != 1 {
		t.Fatalf("drifted = %d", report.Drifted())
	}
	result := resultFor(t, report, "alpha")
	if result.Status != StatusModified || result.PinnedBy != PinnedByReceipt {
		t.Fatalf("result = %+v", result)
	}
	if result.Message == "" {
		t.Fatal("a receipt cannot name the changed file; the report must say so rather than " +
			"leaving an empty change list to read as 'nothing in particular changed'")
	}
}

// Both records exist and disagree. The lock is the pin someone chose deliberately over the
// whole tree, so it decides; the report says which record it used, because re-approving and
// reinstalling are different remedies.
func TestTheLockWinsOverAReceipt(t *testing.T) {
	root := t.TempDir()
	directory := writeSkill(t, root, "alpha")
	pin(t, root)

	tampered := "---\nname: alpha\ndescription: A demo skill.\n---\n\nEdited.\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	writeReceipt(t, root, "alpha") // records the edited bytes as installed

	report := lockAndVerify(t, root)
	result := resultFor(t, report, "alpha")
	if result.Status != StatusModified || result.PinnedBy != PinnedByLock {
		t.Fatalf("result = %+v; the deliberate pin must decide", result)
	}
	if len(result.Changes) != 1 || result.Changes[0].Path != "SKILL.md" {
		t.Fatalf("changes = %+v; a lock pin still names the file that moved", result.Changes)
	}
}

func TestAReceiptWithoutItsSkillIsRemoved(t *testing.T) {
	root := t.TempDir()
	directory := writeSkill(t, root, "alpha")
	writeReceipt(t, root, "alpha")
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}

	report := verifyWithoutLock(t, root)
	if report.Drifted() != 1 {
		t.Fatalf("drifted = %d", report.Drifted())
	}
	result := resultFor(t, report, "alpha")
	if result.Status != StatusRemoved || result.PinnedBy != PinnedByReceipt {
		t.Fatalf("result = %+v", result)
	}
}

// A skill recorded in both places and gone from disk is one fact, not two.
func TestARemovedSkillIsReportedOnce(t *testing.T) {
	root := t.TempDir()
	directory := writeSkill(t, root, "alpha")
	writeReceipt(t, root, "alpha")
	pin(t, root)
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}

	report := lockAndVerify(t, root)
	if report.Drifted() != 1 {
		t.Fatalf("drifted = %d in %+v", report.Drifted(), report.Results)
	}
}

// An unreadable receipt must not pass for an absent one: that would report a recorded skill
// as never recorded, and the caller would exit 0 on a tree it did not manage to check.
func TestAnUnreadableReceiptIsReportedAsUnchecked(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "alpha")
	writeReceipt(t, root, "alpha")

	corrupt := filepath.Join(root, receipt.Directory, "alpha.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	report := verifyWithoutLock(t, root)
	if len(report.Unchecked) != 1 {
		t.Fatalf("unchecked = %+v; a corrupt receipt must be loud", report.Unchecked)
	}
}
