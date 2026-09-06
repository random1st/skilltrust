package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
)

// writeHermesSkill puts a skill on a Hermes host and returns its digest.
func writeHermesSkill(t *testing.T, directory, body string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _, err := marketplace.DigestInstalled(directory)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// writeCuratorLedger appends one record in the shape Hermes's curator writes: absolute paths,
// one JSON object per line.
func writeCuratorLedger(t *testing.T, root, skill, actor, action, when string, files map[string]string) {
	t.Helper()
	after := make([]map[string]string, 0, len(files))
	for path, body := range files {
		sum := sha256.Sum256([]byte(body))
		after = append(after, map[string]string{
			"path": path, "sha256": hex.EncodeToString(sum[:]),
		})
	}
	record := map[string]any{
		"id": "e7bb", "ts": when, "actor": actor, "action": action, "skill": skill,
		"evidence": map[string]string{"session_id": "2026-09-05T19:51"},
		"before":   []map[string]string{},
		"after":    after,
	}
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(root, curatorLedgerName),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

// A Hermes host is found where Hermes actually is. HERMES_HOME is how a fleet host moves it
// off the home directory, and a checker that ignored it would report on a path nobody uses
// and call the machine clean.
func TestHermesIsKnownAndHonoursItsOwnHomeVariable(t *testing.T) {
	hermes, err := lookupAgent("hermes")
	if err != nil {
		t.Fatal(err)
	}
	if !hermes.Managed {
		t.Error("a Hermes host follows a signed catalog; saying otherwise leaves every " +
			"restore and revoke command with nothing to work on")
	}
	if hermes.Layout != layoutLooseSkills {
		t.Errorf("layout = %q, want loose skills: Hermes has no plugin cache", hermes.Layout)
	}

	elsewhere := t.TempDir()
	t.Setenv("HERMES_HOME", elsewhere)
	if home := hermes.Home(); home != elsewhere {
		t.Errorf("home = %s, want the HERMES_HOME override %s", home, elsewhere)
	}

	home := t.TempDir()
	t.Setenv("HERMES_HOME", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if got := hermes.Home(); got != filepath.Join(home, ".hermes") {
		t.Errorf("home = %s, want the default under the user's home", got)
	}
}

// Managed and Layout must agree. They are two fields describing one fact, and the whole
// reason Layout exists is that a single bool meaning both "something is managed here" and
// "it is a plugin cache" was already wrong once.
func TestEveryManagedAgentNamesItsLayout(t *testing.T) {
	for _, known := range agents {
		if known.Managed != (known.Layout != layoutNone) {
			t.Errorf("%s says managed=%v and layout=%q; one of them is wrong",
				known.Name, known.Managed, known.Layout)
		}
	}
}

// Hermes has no hook system at all, so there is no file to write and no moment to take. What
// a person asking for one needs is the command that actually schedules the check — printed in
// full, because "use cron" is not an instruction — and a non-zero exit, so a setup script
// does not record this client as protected.
func TestInstallingAHookForHermesRefusesAndGivesTheCronCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)

	var code int
	output := capture(t, func() { code = runHookInstall([]string{"--agent", "hermes"}) })

	if code == exitClean {
		t.Errorf("a hook that cannot be installed must not exit as a success, got %d", code)
	}
	for _, expected := range []string{
		`hermes cron create "*/30 * * * *" "" --name skilltrust-sync --no-agent --script`,
		"skillctl sync --agent hermes",
		"no hook system",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("the refusal must include %q, got:\n%s", expected, output)
		}
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("nothing may be written for a client that cannot be hooked: %v", entries)
	}
}

// The roots a Hermes host reads, with the names its copies are reported under. A host can
// have both shapes at once, and a profile it does not run must not appear at all.
func TestHermesSkillRootsCoverTheMachineAndEveryProfile(t *testing.T) {
	home := t.TempDir()
	hermes, err := lookupAgent("hermes")
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{
		filepath.Join(home, "skills"),
		filepath.Join(home, "profiles", "operator", "skills"),
		filepath.Join(home, "profiles", "analyst", "skills"),
	} {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A profile directory with no skills directory in it is not a skills root.
	if err := os.MkdirAll(filepath.Join(home, "profiles", "retired"), 0o755); err != nil {
		t.Fatal(err)
	}

	roots := looseSkillRoots(hermes, home)
	labels := map[string]string{}
	for _, root := range roots {
		labels[root.Label] = root.Path
	}
	if len(roots) != 3 {
		t.Fatalf("roots = %+v, want the machine root and two profiles", roots)
	}
	if labels[""] != filepath.Join(home, "skills") {
		t.Errorf("the machine root must be unlabelled, got %+v", roots)
	}
	if labels["operator"] != filepath.Join(home, "profiles", "operator", "skills") ||
		labels["analyst"] != filepath.Join(home, "profiles", "analyst", "skills") {
		t.Errorf("each profile must be labelled with its own name, got %+v", roots)
	}
}

// The reason this adapter exists. A Hermes host edits its own skills as a matter of course
// and its curator writes down that it did; reporting those edits as tampering would bury the
// real finding among the ordinary ones, and a report nobody can read protects nothing.
func TestACuratorRecordedEditReadsAsAdoptedRatherThanTampering(t *testing.T) {
	home := t.TempDir()
	hermes, err := lookupAgent("hermes")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "profiles", "operator", "skills")
	published := "---\nname: aws-readonly\n---\nread only\n"
	digest := writeHermesSkill(t, filepath.Join(t.TempDir(), "aws-readonly"), published)

	edited := "---\nname: aws-readonly\n---\nread only, in eu-west-1\n"
	skill := filepath.Join(root, "aws-readonly")
	writeHermesSkill(t, skill, edited)
	writeCuratorLedger(t, root, "aws-readonly", "agent", "patch", "2026-09-05T19:51:07.375741+00:00",
		map[string]string{filepath.Join(skill, "SKILL.md"): edited})

	snapshot := &catalog.Snapshot{Name: "acme", Skills: []catalog.Managed{
		{Name: "aws-readonly", Digest: digest},
	}}
	roots := looseSkillRoots(hermes, home)
	locate := marketplace.LooseSkills(roots)
	results := marketplace.Reconcile(snapshot, marketplace.Options{
		Locate:  locate,
		Adopted: mergeAdoptions(marketplace.Adoptions{}, curatorLedgerAdoptions(snapshot, roots, locate)),
	})

	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Outcome != marketplace.OutcomeAdapted {
		t.Fatalf("outcome = %q, want a curator's edit to read as adopted", results[0].Outcome)
	}
	if results[0].Copy != "operator" {
		t.Errorf("copy = %q, want the profile the edit is in", results[0].Copy)
	}
	// The reason names the ledger rather than pretending a person typed it here.
	for _, expected := range []string{"curator ledger", "agent", "patch", "session"} {
		if !strings.Contains(results[0].Adapted, expected) {
			t.Errorf("reason %q is missing %q", results[0].Adapted, expected)
		}
	}
	if results[0].AdaptedSince.IsZero() {
		t.Error("the record's own timestamp must survive, so a workaround's age is visible")
	}
	// Adapted is never quiet: an organisation must still see that this host runs bytes
	// nobody signed.
	if results[0].Outcome.Settled() {
		t.Error("an adopted difference must stay visible in the report")
	}
}

// The ledger vouches for exact bytes and nothing more. Anything that happens after the
// curator's last entry — an edit, or a file appearing beside the skill — takes the adoption
// with it, which is what stops the ledger from being an off switch anything on the host could
// reach for.
func TestALedgerThatNoLongerMatchesTheDiskAdoptsNothing(t *testing.T) {
	hermes, err := lookupAgent("hermes")
	if err != nil {
		t.Fatal(err)
	}
	published := "---\nname: aws-readonly\n---\nread only\n"
	recorded := "---\nname: aws-readonly\n---\nrecorded by the curator\n"

	cases := map[string]func(t *testing.T, skill string){
		"edited again after the record": func(t *testing.T, skill string) {
			if err := os.WriteFile(filepath.Join(skill, "SKILL.md"),
				[]byte("---\nname: aws-readonly\n---\nsomething else entirely\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a file the record never mentioned": func(t *testing.T, skill string) {
			if err := os.WriteFile(
				filepath.Join(skill, "extra.md"), []byte("added later\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a file the record names is gone": func(t *testing.T, skill string) {
			if err := os.Remove(filepath.Join(skill, "SKILL.md")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(skill, "other.md"), []byte("moved\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, "profiles", "operator", "skills")
			skill := filepath.Join(root, "aws-readonly")
			digest := writeHermesSkill(t, filepath.Join(t.TempDir(), "aws-readonly"), published)
			writeHermesSkill(t, skill, recorded)
			writeCuratorLedger(t, root, "aws-readonly", "curator", "patch",
				"2026-09-05T19:51:07.375741+00:00",
				map[string]string{filepath.Join(skill, "SKILL.md"): recorded})

			tamper(t, skill)

			snapshot := &catalog.Snapshot{Name: "acme", Skills: []catalog.Managed{
				{Name: "aws-readonly", Digest: digest},
			}}
			roots := looseSkillRoots(hermes, home)
			locate := marketplace.LooseSkills(roots)
			adoptions := curatorLedgerAdoptions(snapshot, roots, locate)
			if len(adoptions.Entries) != 0 {
				t.Fatalf("the ledger vouched for bytes it does not describe: %+v", adoptions.Entries)
			}
			results := marketplace.Reconcile(snapshot, marketplace.Options{
				Locate: locate, Adopted: adoptions,
			})
			if len(results) != 1 || results[0].Outcome != marketplace.OutcomeChanged {
				t.Fatalf("results = %+v, want a finding", results)
			}
		})
	}
}

// The newest record wins, because the file is append-only and an earlier one describes bytes
// that have since been replaced. A malformed line must cost nothing: it belongs to another
// program, and one bad line must not decide that every curated skill here is tampering.
func TestTheLedgerIsReadNewestFirstAndSurvivesJunk(t *testing.T) {
	hermes, err := lookupAgent("hermes")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	root := filepath.Join(home, "skills")
	skill := filepath.Join(root, "aws-readonly")
	current := "---\nname: aws-readonly\n---\nthe current edit\n"
	digest := writeHermesSkill(t, filepath.Join(t.TempDir(), "aws-readonly"),
		"---\nname: aws-readonly\n---\npublished\n")
	writeHermesSkill(t, skill, current)

	// An older record for bytes that are gone, a line that is not JSON, then the current one.
	writeCuratorLedger(t, root, "aws-readonly", "agent", "create", "2026-09-01T10:00:00+00:00",
		map[string]string{filepath.Join(skill, "SKILL.md"): "an older edit\n"})
	if err := os.WriteFile(filepath.Join(root, curatorLedgerName),
		append(mustRead(t, filepath.Join(root, curatorLedgerName)), []byte("{not json\n")...),
		0o644); err != nil {
		t.Fatal(err)
	}
	writeCuratorLedger(t, root, "aws-readonly", "agent", "patch", "2026-09-05T19:51:07+00:00",
		map[string]string{filepath.Join(skill, "SKILL.md"): current})

	snapshot := &catalog.Snapshot{Name: "acme", Skills: []catalog.Managed{
		{Name: "aws-readonly", Digest: digest},
	}}
	roots := looseSkillRoots(hermes, home)
	locate := marketplace.LooseSkills(roots)
	results := marketplace.Reconcile(snapshot, marketplace.Options{
		Locate:  locate,
		Adopted: curatorLedgerAdoptions(snapshot, roots, locate),
	})
	if len(results) != 1 || results[0].Outcome != marketplace.OutcomeAdapted {
		t.Fatalf("results = %+v, want the newest record to vouch for what is on disk", results)
	}
	if !strings.Contains(results[0].Adapted, "patch") {
		t.Errorf("the newest record's own words must be the ones reported: %q", results[0].Adapted)
	}
}

// A record in the adoptions file is somebody's decision. One derived from a ledger is this
// tool's reading of another program's log. Where both describe the same copy, the person's
// wins — they are the only one of the two who can be asked what they meant.
func TestAPersonsOwnAdoptionOutranksOneDerivedFromTheLedger(t *testing.T) {
	owned := marketplace.Adoptions{Entries: []marketplace.Adoption{{
		Marketplace: "acme", Plugin: "aws-readonly", Copy: "operator",
		From: "sha256:published", Local: "sha256:mine",
		Reason: "I decided this", Since: time.Now(),
	}}}
	derived := marketplace.Adoptions{Entries: []marketplace.Adoption{
		{
			Marketplace: "acme", Plugin: "aws-readonly", Copy: "operator",
			From: "sha256:published", Local: "sha256:mine", Reason: "curator ledger: agent patch",
		},
		{
			Marketplace: "acme", Plugin: "other-skill", Copy: "analyst",
			From: "sha256:published", Local: "sha256:theirs", Reason: "curator ledger: agent patch",
		},
	}}

	merged := mergeAdoptions(owned, derived)
	if len(merged.Entries) != 2 {
		t.Fatalf("merged = %+v, want the conflict resolved and the rest kept", merged.Entries)
	}
	found, ok := merged.FindCopy("acme", "aws-readonly", "operator")
	if !ok || found.Reason != "I decided this" {
		t.Errorf("the person's own reason was replaced: %+v", found)
	}
	if _, ok := merged.FindCopy("acme", "other-skill", "analyst"); !ok {
		t.Error("a derived adoption with no conflict must survive the merge")
	}
}

// The report has to say which copy a line is about. Two profiles produce two lines with the
// same skill name, and a person cannot act on a line that does not say which file it means.
func TestTheReportNamesTheCopyAndTheDirectoriesItRead(t *testing.T) {
	roots := []string{"/srv/hermes/profiles/operator/skills", "/srv/hermes/skills"}
	output := capture(t, func() {
		writeReconcileReport([]marketplace.Result{
			{Outcome: marketplace.OutcomeChanged, Plugin: "aws-readonly", Copy: "operator"},
			{Outcome: marketplace.OutcomeAdapted, Plugin: "aws-readonly",
				Adapted: "curator ledger: agent patch"},
		}, nil, "/srv/hermes", true, roots...)
	})

	if !strings.Contains(output, "operator/aws-readonly") {
		t.Errorf("the copy must appear in the line it belongs to:\n%s", output)
	}
	// A copy with no name is still just the skill; inventing a prefix would be noise.
	if !strings.Contains(output, "adapted       aws-readonly") {
		t.Errorf("an unlabelled copy must be reported by name alone:\n%s", output)
	}
	for _, root := range roots {
		if !strings.Contains(output, root) {
			t.Errorf("the report must say where it looked; %s is missing:\n%s", root, output)
		}
	}
	if strings.Contains(output, "plugins/cache") {
		t.Errorf("a Hermes host has no plugin cache and must not be told it was checked:\n%s",
			output)
	}
}

// Result.Copy has to survive to the JSON a dashboard reads, or an organisation sees two
// identical findings and cannot tell them apart.
func TestTheCopySurvivesIntoTheReportedJSON(t *testing.T) {
	encoded, err := json.Marshal(marketplace.Result{
		Plugin: "aws-readonly", Copy: "operator", Outcome: marketplace.OutcomeChanged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"copy":"operator"`) {
		t.Fatalf("copy is not reported: %s", encoded)
	}
	// And a client with one copy adds no field at all, so nothing existing changes shape.
	encoded, err = json.Marshal(marketplace.Result{
		Plugin: "runbook", Outcome: marketplace.OutcomeVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "copy") {
		t.Fatalf("an unlabelled copy must not appear in the JSON: %s", encoded)
	}
}

// The whole command, on a host shaped like a real one: a followed catalog, a profile whose
// copy was edited, and no plugin cache anywhere. Everything above was a piece of this; if
// sync itself does not reach the loose directories, none of the pieces matter.
func TestSyncAgainstAHermesHostChecksTheProfileDirectories(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", state)
	userHome := t.TempDir()
	t.Setenv("HOME", userHome)
	t.Setenv("USERPROFILE", userHome)

	// A machine key, so filing the check is the ordinary path rather than a failure this
	// test would then be measuring instead of the report.
	_, machinePrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), machinePrivate); err != nil {
		t.Fatal(err)
	}

	publisher, publisherPrivate, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.PinKey(defaultTrustedKeys(), "publisher", publisher); err != nil {
		t.Fatal(err)
	}

	hermesHome := t.TempDir()
	t.Setenv("HERMES_HOME", hermesHome)
	published := "---\nname: aws-readonly\n---\nread only\n"
	digest := writeHermesSkill(t, filepath.Join(t.TempDir(), "aws-readonly"), published)

	// One profile keeps the published bytes, the other was edited here.
	writeHermesSkill(t,
		filepath.Join(hermesHome, "profiles", "analyst", "skills", "aws-readonly"), published)
	writeHermesSkill(t,
		filepath.Join(hermesHome, "profiles", "operator", "skills", "aws-readonly"),
		"---\nname: aws-readonly\n---\nread only, in eu-west-1\n")

	subscription := Subscription{
		Name:       "acme",
		Repository: "/no/such/repository",
		KeyIDs:     []string{attest.KeyID(publisher)},
	}
	if err := saveSubscriptions([]Subscription{subscription}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	writeCatalogIndex(t, subscription, catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: "acme", Sequence: 1,
		IssuedAt: now, ValidUntil: now.Add(time.Hour),
		Skills: []catalog.Managed{
			{Name: "aws-readonly", Digest: digest, Path: "skills/aws-readonly"},
		},
	}, publisherPrivate)

	var code int
	output := capture(t, func() {
		code = runSync([]string{"--agent", "hermes", "--offline", "--report-only"})
	})
	if code != exitFindings {
		t.Fatalf("sync = %d, want the edited profile reported as a finding:\n%s", code, output)
	}
	if !strings.Contains(output, "operator/aws-readonly") {
		t.Errorf("the edited profile is not named in the report:\n%s", output)
	}
	if strings.Contains(output, "analyst/aws-readonly") {
		t.Errorf("the untouched profile verified and must not be a finding:\n%s", output)
	}
	if !strings.Contains(output, "1 verified") {
		t.Errorf("the profile holding the published bytes must be counted:\n%s", output)
	}
	if strings.Contains(output, "plugins/cache") {
		t.Errorf("a Hermes host has no plugin cache to have checked:\n%s", output)
	}

	// --report-only means what it says.
	body, err := os.ReadFile(filepath.Join(
		hermesHome, "profiles", "operator", "skills", "aws-readonly", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "eu-west-1") {
		t.Fatal("a report-only run changed the file it was reporting on")
	}
}

// --claude-home named Claude on a command that now checks four clients. The clearer name has
// to work and the old one has to keep working: renaming a flag people have in cron jobs buys
// clarity for new readers by breaking machines that already run.
func TestBothHomeFlagsNameTheSameDirectory(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", state)
	userHome := t.TempDir()
	t.Setenv("HOME", userHome)
	t.Setenv("USERPROFILE", userHome)
	// No subscriptions: the run stops before any check, which is enough to see how the
	// flags were parsed and keeps this test away from the network.
	if err := saveSubscriptions(nil); err != nil {
		t.Fatal(err)
	}

	hermesHome := t.TempDir()
	writeHermesSkill(t, filepath.Join(hermesHome, "skills", "aws-readonly"), "read only\n")

	for _, flag := range []string{"--home", "--claude-home"} {
		if code := runSync([]string{"--agent", "hermes", flag, hermesHome, "--offline"}); code != exitUsage {
			t.Errorf("%s: sync = %d, want the no-subscriptions refusal", flag, code)
		}
	}
	// Given both and disagreeing, it refuses rather than silently picking one.
	code := runSync([]string{
		"--agent", "hermes", "--home", hermesHome, "--claude-home", t.TempDir(), "--offline",
	})
	if code != exitUsage {
		t.Errorf("two different homes must be refused, got %d", code)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(fmt.Errorf("reading %s: %w", path, err))
	}
	return body
}
