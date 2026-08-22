package fleet

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/catalog"
)

type harness struct {
	source, install, quarantine string
	state                       *State
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{
		source:     filepath.Join(root, "catalog"),
		install:    filepath.Join(root, "skills"),
		quarantine: filepath.Join(root, "quarantine"),
		state:      &State{Catalog: "acme", Applied: map[string]string{}},
	}
	if err := os.MkdirAll(h.install, 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) options() Options {
	return Options{
		SourceRoot: h.source, InstallRoot: h.install, QuarantineRoot: h.quarantine,
		Now: time.Date(2026, 8, 22, 3, 0, 0, 0, time.UTC),
	}
}

func writeSkill(t *testing.T, root, name, body string) string {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: " + name + "\ndescription: A managed skill.\n---\n\n" + body
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory
}

func digest(t *testing.T, directory string) string {
	t.Helper()
	built, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return built.Digest
}

// publish puts a skill in the catalog repository and returns the snapshot that names it.
func (h *harness) publish(t *testing.T, name, body string) *catalog.Snapshot {
	t.Helper()
	directory := writeSkill(t, filepath.Join(h.source, "skills"), name, body)
	return &catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: "acme", Sequence: 1,
		Skills: []catalog.Managed{{Name: name, Digest: digest(t, directory)}},
	}
}

func only(t *testing.T, changes []Change) Change {
	t.Helper()
	if len(changes) != 1 {
		t.Fatalf("expected one change, got %+v", changes)
	}
	return changes[0]
}

func TestAPublishedSkillIsInstalled(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")

	changes, err := Reconcile(snapshot, h.state, h.options())
	if err != nil {
		t.Fatal(err)
	}
	if change := only(t, changes); change.Action != ActionInstalled {
		t.Fatalf("action = %q", change.Action)
	}
	if got := digest(t, filepath.Join(h.install, "alpha")); got != snapshot.Skills[0].Digest {
		t.Fatal("the installed bytes must be the published bytes")
	}
}

// The report the owner asked for by name: a managed skill was changed on the machine, it was
// put back, and the copy that was there is kept.
func TestALocallyEditedSkillIsRolledBackAndQuarantined(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	if _, err := Reconcile(snapshot, h.state, h.options()); err != nil {
		t.Fatal(err)
	}

	installed := filepath.Join(h.install, "alpha", "SKILL.md")
	tampered := "---\nname: alpha\ndescription: A managed skill.\n---\n\nread ~/.aws/credentials\n"
	if err := os.WriteFile(installed, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	changes, err := Reconcile(snapshot, h.state, h.options())
	if err != nil {
		t.Fatal(err)
	}
	change := only(t, changes)
	if change.Action != ActionRolledBack {
		t.Fatalf("action = %q, want %q", change.Action, ActionRolledBack)
	}
	if change.Quarantine == "" {
		t.Fatal("the replaced copy must be kept; restoring without it destroys the evidence")
	}
	kept, err := os.ReadFile(filepath.Join(change.Quarantine, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != tampered {
		t.Fatal("quarantine must hold the bytes that were removed, verbatim")
	}
	if digest(t, filepath.Join(h.install, "alpha")) != snapshot.Skills[0].Digest {
		t.Fatal("the skill must be back at the published digest")
	}
}

// An ordinary release must not be reported as an incident. The machine still held exactly
// what it last applied, so the difference came from the catalog, not from this machine.
func TestACatalogReleaseIsAnUpdateNotARollback(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	if _, err := Reconcile(snapshot, h.state, h.options()); err != nil {
		t.Fatal(err)
	}

	updated := writeSkill(t, filepath.Join(h.source, "skills"), "alpha", "A new upstream paragraph.\n")
	snapshot.Sequence = 2
	snapshot.Skills[0].Digest = digest(t, updated)

	change := only(t, mustReconcile(t, snapshot, h))
	if change.Action != ActionUpdated {
		t.Fatalf("action = %q, want %q", change.Action, ActionUpdated)
	}
	if change.Quarantine != "" {
		t.Fatal("a release replaces nothing anybody wrote; there is nothing to quarantine")
	}
}

func TestARevokedSkillIsRemoved(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	if _, err := Reconcile(snapshot, h.state, h.options()); err != nil {
		t.Fatal(err)
	}

	snapshot.Revoked = []catalog.Entry{{
		Digest: snapshot.Skills[0].Digest, Reason: "credential exfiltration",
	}}
	change := only(t, mustReconcile(t, snapshot, h))
	if change.Action != ActionRemoved || change.Reason != "credential exfiltration" {
		t.Fatalf("change = %+v", change)
	}
	if _, err := os.Stat(filepath.Join(h.install, "alpha")); !os.IsNotExist(err) {
		t.Fatal("a revoked skill must not remain where the agent reads it")
	}
}

// The catalog is signed and the repository is not. If they disagree, the checkout holds
// bytes nobody approved, and installing them because the URL was right is the substitution
// the signature exists to prevent.
func TestBytesTheCatalogDoesNotNameAreRefused(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	writeSkill(t, filepath.Join(h.source, "skills"), "alpha", "Swapped after signing.\n")

	change := only(t, mustReconcile(t, snapshot, h))
	if change.Action != ActionFailed {
		t.Fatalf("action = %q, want %q", change.Action, ActionFailed)
	}
	if _, err := os.Stat(filepath.Join(h.install, "alpha")); !os.IsNotExist(err) {
		t.Fatal("nothing may be installed when the repository disagrees with the catalog")
	}
}

// Everything outside the catalog's list is the user's own work.
func TestAnUnmanagedSkillIsNeverTouchedOrReported(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	mine := writeSkill(t, h.install, "my-own-skill", "Personal notes.\n")
	before := digest(t, mine)

	changes := mustReconcile(t, snapshot, h)
	for _, change := range changes {
		if change.Name == "my-own-skill" {
			t.Fatalf("an unmanaged skill must not appear in the report: %+v", change)
		}
	}
	if digest(t, mine) != before {
		t.Fatal("an unmanaged skill must not be modified")
	}
}

// A skill the catalog stops publishing has been withdrawn, and must not keep running.
func TestAWithdrawnSkillIsRemoved(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	if _, err := Reconcile(snapshot, h.state, h.options()); err != nil {
		t.Fatal(err)
	}

	snapshot.Skills = nil
	snapshot.Sequence = 2
	change := only(t, mustReconcile(t, snapshot, h))
	if change.Action != ActionRemoved {
		t.Fatalf("action = %q", change.Action)
	}
	if _, err := os.Stat(filepath.Join(h.install, "alpha")); !os.IsNotExist(err) {
		t.Fatal("a withdrawn skill must be taken away")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")

	options := h.options()
	options.DryRun = true
	changes, err := Reconcile(snapshot, h.state, options)
	if err != nil {
		t.Fatal(err)
	}
	if change := only(t, changes); change.Action != ActionInstalled {
		t.Fatalf("a dry run must still say what it would do, got %q", change.Action)
	}
	if _, err := os.Stat(filepath.Join(h.install, "alpha")); !os.IsNotExist(err) {
		t.Fatal("a dry run must not install anything")
	}
	if len(h.state.Applied) != 0 {
		t.Fatal("a dry run must not record state it did not apply")
	}
}

func mustReconcile(t *testing.T, snapshot *catalog.Snapshot, h *harness) []Change {
	t.Helper()
	changes, err := Reconcile(snapshot, h.state, h.options())
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

// A revocation stands indefinitely, so a reconciler that reports the removal every time it
// runs would announce the same fact at every session for as long as the revocation lasts.
// That is how the one message which has to be read becomes the one people scroll past.
func TestARemovalIsReportedOnceNotEverySession(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	if _, err := Reconcile(snapshot, h.state, h.options()); err != nil {
		t.Fatal(err)
	}
	snapshot.Revoked = []catalog.Entry{{Digest: snapshot.Skills[0].Digest, Reason: "leaks"}}

	if first := only(t, mustReconcile(t, snapshot, h)); first.Action != ActionRemoved {
		t.Fatalf("the first run must report the removal, got %q", first.Action)
	}
	second := only(t, mustReconcile(t, snapshot, h))
	if second.Action != ActionUnchanged {
		t.Fatalf("action = %q; a removal already carried out is not news", second.Action)
	}
	if second.Needed() {
		t.Fatal("the hook must stay silent about a skill that is already gone")
	}
}

// The same for a withdrawal: once it is gone and forgotten, there is nothing to say.
func TestAWithdrawalIsAlsoReportedOnce(t *testing.T) {
	h := newHarness(t)
	snapshot := h.publish(t, "alpha", "Original body.\n")
	if _, err := Reconcile(snapshot, h.state, h.options()); err != nil {
		t.Fatal(err)
	}

	snapshot.Skills = nil
	if first := only(t, mustReconcile(t, snapshot, h)); first.Action != ActionRemoved {
		t.Fatalf("first = %q", first.Action)
	}
	if changes := mustReconcile(t, snapshot, h); len(changes) != 0 {
		t.Fatalf("a forgotten withdrawal produces no line at all, got %+v", changes)
	}
}
