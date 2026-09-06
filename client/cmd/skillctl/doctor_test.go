package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/archive"
)

func doctorFixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", filepath.Join(base, "state"))
	root := filepath.Join(base, ".agents", "skills")
	setDoctorRoots(t, root)
	return base, root
}

func setDoctorRoots(t *testing.T, roots ...string) {
	t.Helper()
	previous := doctorRootCandidates
	doctorRootCandidates = func() []string { return roots }
	t.Cleanup(func() { doctorRootCandidates = previous })
}

func doctorResult(t *testing.T, run func([]string) int, args ...string) (machineStatus, int) {
	t.Helper()
	var code int
	raw := capture(t, func() { code = run(args) })
	var out machineStatus
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("result was not one JSON document: %v\n%s", err, raw)
	}
	return out, code
}

func assertDoctorDidNotCreateKeys(t *testing.T) {
	t.Helper()
	for _, path := range []string{defaultSigningKey(), defaultPublicKey(), latestCheckPath(CheckScopeManaged), connectStatePath()} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("read-only inventory created %s: %v", path, err)
		}
	}
}

func assertDoctorObservation(t *testing.T, inventory *skillInventory, name, path, verdict string) {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, skill := range inventory.Skills {
		if skill.Path == resolved {
			if skill.Name != name || skill.Verdict != verdict {
				t.Fatalf("wrong verdict for %s: %+v", resolved, skill)
			}
			return
		}
	}
	t.Fatalf("inventory omitted the exact skill path %s: %+v", resolved, inventory.Skills)
}

func TestDoctorEmptyMachineIsNotGreenAndCreatesNothing(t *testing.T) {
	doctorFixture(t)
	for _, run := range []func([]string) int{
		runDoctor,
		func(args []string) int { return runStatus(append(args, "--refresh")) },
	} {
		out, code := doctorResult(t, run, "--json")
		if code != exitFindings || out.Status != "needs_attention" || out.Inventory == nil {
			t.Fatalf("empty machine looked checked: %+v, exit %d", out, code)
		}
		inventory := out.Inventory
		if inventory.Skills == nil || len(inventory.Skills) != 0 {
			t.Fatalf("empty inventory must return an empty skill list: %+v", inventory.Skills)
		}
		if inventory.Found != 0 || inventory.Verified != 0 || inventory.Unapproved != 0 || inventory.Changed != 0 || inventory.Errors != 0 || inventory.TrustedKeys != 0 {
			t.Fatalf("empty inventory: %+v", inventory)
		}
		if out.LastCheck != nil || out.ReportAccepted || !reflect.DeepEqual(out.NextCommand, []string{"skillctl", "subscribe", "--help"}) {
			t.Fatalf("invented check or unusable next command: %+v", out)
		}
	}
	if _, err := os.Lstat(Home()); !os.IsNotExist(err) {
		t.Fatalf("doctor created state on an empty machine: %v", err)
	}
}

func TestDoctorCountsUnapprovedLooseSkillsAndPluginCachesOnce(t *testing.T) {
	base, root := doctorFixture(t)
	loose := writeSkill(t, base, "loose", "---\nname: loose\ndescription: example\n---\nLocal skill.\n")
	cache := filepath.Join(base, ".claude", "plugins", "cache")
	plugin := filepath.Join(cache, "publisher", "plugin", "1.0.0", "skills", "cached")
	if err := os.MkdirAll(plugin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "SKILL.md"), []byte("---\nname: cached\ndescription: example\n---\nCached skill.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "same-skills")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	// Exercise the real root construction with only owned bases and agent homes.
	known, err := lookupAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	previousAgents := agents
	agents = []agent{known}
	t.Cleanup(func() { agents = previousAgents })
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(base, ".claude"))
	candidates := installedSkillRootCandidates([]string{base})
	setDoctorRoots(t, append(candidates, alias, plugin)...)
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 2 || out.Inventory.Unapproved != 2 || out.Inventory.Verified != 0 || out.Inventory.Errors != 0 {
		t.Fatalf("unsigned inventory: %+v, exit %d", out, code)
	}
	if out.Inventory.Scope != "local_skill_directories_and_plugin_caches" || out.NextAction == nil || out.NextAction.Code != "review_skill" {
		t.Fatalf("scope or next action missing: %+v", out)
	}
	if len(out.Inventory.Skills) != 2 {
		t.Fatalf("inventory lost or duplicated skill paths: %+v", out.Inventory.Skills)
	}
	assertDoctorObservation(t, out.Inventory, "loose", loose, "unapproved")
	assertDoctorObservation(t, out.Inventory, "cached", plugin, "unapproved")
	if !reflect.DeepEqual(out.NextCommand, []string{commandName(), "lint", out.Inventory.Skills[0].Path}) {
		t.Fatalf("next command does not review the first unapproved skill: %v", out.NextCommand)
	}
	status, statusCode := doctorResult(t, runStatus, "--refresh", "--json")
	out.Inventory.CheckedAt, status.Inventory.CheckedAt = time.Time{}, time.Time{}
	if statusCode != code || !reflect.DeepEqual(out, status) {
		t.Fatalf("doctor and status used different first-verdict paths:\n%+v\n%+v", out, status)
	}
	human := capture(t, func() { runDoctor(nil) })
	for _, want := range []string{"Found: 2", "verified: 0", "unapproved: 2", "cached versions may be inactive", "no trusted approval basis", "Run: skillctl lint ", `"cached"`, `"loose"`} {
		if !strings.Contains(human, want) {
			t.Fatalf("human verdict lacks %q: %s", want, human)
		}
	}
	if _, err := os.Lstat(Home()); !os.IsNotExist(err) {
		t.Fatalf("unsigned inventory created configuration: %v", err)
	}
}

func approveDoctorSkill(t *testing.T, directory, name string) string {
	t.Helper()
	public, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := attest.SaveTrustedKeys(defaultTrustedKeys(), map[string]ed25519.PublicKey{"fixture-publisher": public}); err != nil {
		t.Fatal(err)
	}
	built, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := attest.Sign(attest.Statement{
		Subject: attest.Subject{Name: name, Digest: built.Digest}, ApprovedBy: "publisher@example.test", ApprovedAt: time.Now(),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	path := attest.StorePath(homePath(attest.StoreDirectory), name, directory)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDoctorVerifiesExistingApprovalWithoutClaimingSessionProtection(t *testing.T) {
	base, _ := doctorFixture(t)
	skill := writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
	approveDoctorSkill(t, skill, "review")
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitClean || out.Status != "approvals_checked" || out.Inventory.Found != 1 || out.Inventory.Verified != 1 || out.Inventory.Unapproved != 0 || out.Inventory.Errors != 0 {
		t.Fatalf("valid existing approval: %+v, exit %d", out, code)
	}
	if out.LastCheck != nil || out.ReportAccepted || len(out.Hooks) != 0 || out.NextAction != nil || strings.Contains(out.Title, "session") {
		t.Fatalf("a current observation claimed protection it did not establish: %+v", out)
	}
	assertDoctorObservation(t, out.Inventory, "review", skill, "verified")
	assertDoctorDidNotCreateKeys(t)
}

func TestDoctorPreservesChangedApprovedSkillAndGivesItsRealPath(t *testing.T) {
	base, _ := doctorFixture(t)
	skill := writeSkill(t, base, "review ' notes", "---\nname: review\ndescription: example\n---\nReview.\n")
	approval := approveDoctorSkill(t, skill, "review")
	approvalBefore, err := os.ReadFile(approval)
	if err != nil {
		t.Fatal(err)
	}
	pinsBefore, err := os.ReadFile(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("---\nname: review\ndescription: example\n---\nChanged instructions.\n")
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), changed, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Changed != 1 || out.Inventory.Verified != 0 || out.Inventory.Unapproved != 0 || out.Inventory.Errors != 0 {
		t.Fatalf("changed approval verdict: %+v, exit %d", out, code)
	}
	assertDoctorObservation(t, out.Inventory, "review", skill, "changed")
	resolved, err := filepath.EvalSymlinks(skill)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.NextCommand, []string{"skillctl", "digest", resolved}) || !strings.Contains(out.Inventory.Details, "approved ") || !strings.Contains(out.Inventory.Details, "on disk ") {
		t.Fatalf("missing real diagnostic command or comparison: %+v", out)
	}
	human := capture(t, func() { runDoctor(nil) })
	if !strings.Contains(human, "Run: skillctl digest '") || !strings.Contains(human, "'\"'\"'") {
		t.Fatalf("next command did not quote the real skill path: %s", human)
	}
	for path, want := range map[string][]byte{filepath.Join(skill, "SKILL.md"): changed, approval: approvalBefore, defaultTrustedKeys(): pinsBefore} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("doctor changed %s: %v", path, err)
		}
	}
	assertDoctorDidNotCreateKeys(t)
}

func TestDoctorUnapprovedNamesakeDoesNotBorrowVerifiedCoverage(t *testing.T) {
	base, _ := doctorFixture(t)
	skill := writeSkill(t, base, "approved", "---\nname: shared\ndescription: example\n---\nApproved.\n")
	approveDoctorSkill(t, skill, "shared")
	unapproved := writeSkill(t, base, "unapproved", "---\nname: shared\ndescription: example\n---\nUnapproved.\n")
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 2 || out.Inventory.Verified != 1 || out.Inventory.Unapproved != 1 || out.Inventory.Changed != 0 || out.Inventory.Errors != 0 {
		t.Fatalf("an unapproved namesake borrowed green coverage: %+v, exit %d", out, code)
	}
	if len(out.Inventory.Skills) != 2 {
		t.Fatalf("same-name copies collapsed into one item: %+v", out.Inventory.Skills)
	}
	assertDoctorObservation(t, out.Inventory, "shared", skill, "verified")
	assertDoctorObservation(t, out.Inventory, "shared", unapproved, "unapproved")
	resolved, err := filepath.EvalSymlinks(unapproved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.NextCommand, []string{commandName(), "lint", resolved}) {
		t.Fatalf("next command selected the approved namesake: %v", out.NextCommand)
	}
}

func TestDoctorUnapprovedSkillReadErrorIsNotUnapproved(t *testing.T) {
	base, _ := doctorFixture(t)
	skill := writeSkill(t, base, "unreadable", "---\nname: unreadable\ndescription: example\n---\nRead.\n")
	// Canonical archives reject links inside a skill, independent of test UID.
	if err := os.Symlink(filepath.Join(skill, "SKILL.md"), filepath.Join(skill, "linked.md")); err != nil {
		t.Fatal(err)
	}
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Errors != 1 || out.Inventory.Unapproved != 0 || out.Inventory.Verified != 0 || !strings.Contains(out.Inventory.Details, "could not be read") {
		t.Fatalf("a read error disappeared into unapproved: %+v, exit %d", out, code)
	}
	assertDoctorObservation(t, out.Inventory, "unreadable", skill, "error")
	if out.Inventory.Skills[0].Error == "" {
		t.Fatal("the per-skill error had no diagnostic")
	}
	assertDoctorDidNotCreateKeys(t)
}

func TestDoctorUnapprovedNextCommandUsesTheExactPathWithoutApprovingIt(t *testing.T) {
	base, _ := doctorFixture(t)
	body := "---\nname: review\ndescription: example\n---\nReview existing instructions.\n"
	skill := writeSkill(t, base, "my notes ' ; $(printf injected)", body)
	out, code := doctorResult(t, runDoctor, "--json")
	resolved, err := filepath.EvalSymlinks(skill)
	if err != nil {
		t.Fatal(err)
	}
	if code != exitFindings || !reflect.DeepEqual(out.NextCommand, []string{commandName(), "lint", resolved}) || !strings.Contains(out.NextAction.Detail, "does not approve") {
		t.Fatalf("unapproved skill has no concrete review command: %+v, exit %d", out, code)
	}
	assertDoctorObservation(t, out.Inventory, "review", skill, "unapproved")
	human := capture(t, func() { runDoctor(nil) })
	if !strings.Contains(human, "Run: skillctl lint '") || !strings.Contains(human, "'\"'\"'") || !strings.Contains(human, strconv.Quote(resolved)) {
		t.Fatalf("terminal output did not preserve and quote the path: %s", human)
	}
	got, err := os.ReadFile(filepath.Join(skill, "SKILL.md"))
	if err != nil || string(got) != body {
		t.Fatalf("doctor changed an unapproved skill: %v", err)
	}
	for _, path := range []string{Home(), attest.DefaultName(skill)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("doctor created state or an approval at %s: %v", path, err)
		}
	}
}

func TestDoctorTerminalListEscapesUntrustedNamesAndPaths(t *testing.T) {
	for _, unusual := range []string{"\nverified\x1b[2J", "\u202everified\u2066"} {
		skill := skillObservation{Name: "review" + unusual, Path: "/skills/notes" + unusual, Verdict: "unapproved"}
		out := machineStatus{Status: "needs_attention", Inventory: &skillInventory{Found: 1, Unapproved: 1, Skills: []skillObservation{skill}}, NextCommand: []string{commandName(), "lint", skill.Path}}
		human := capture(t, func() { writeMachineStatus(out, false) })
		if strings.Contains(human, unusual) || !strings.Contains(human, strconv.Quote(skill.Name)) || !strings.Contains(human, strconv.Quote(skill.Path)) || !strings.Contains(human, "Next command arguments (escaped):") {
			t.Fatalf("untrusted metadata forged terminal verdict lines: %q", human)
		}
		var decoded machineStatus
		if err := json.Unmarshal([]byte(capture(t, func() { writeMachineStatus(out, true) })), &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.NextCommand, out.NextCommand) {
			t.Fatalf("JSON changed the exact command arguments: %q", decoded.NextCommand)
		}
	}
}

func TestDoctorObservationsDoNotEnterReportProjections(t *testing.T) {
	base, root := doctorFixture(t)
	skill := writeSkill(t, base, "local-only-skill-name", "---\nname: local-only-skill-name\ndescription: example\n---\nReview.\n")
	summary, _, code := inspectSkillRoots(attest.NewTrustedKeys(), true, []string{root}, io.Discard, io.Discard)
	if code != exitClean || len(summary.Observations) != 1 {
		t.Fatalf("the existing verifier did not populate local observations: %+v, exit %d", summary, code)
	}
	for _, projection := range []any{summary, looseSkillCurrentCheck(summary)} {
		raw, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"local-only-skill-name", skill, `"skills"`, `"Observations"`, `"observations"`, `"path"`} {
			if strings.Contains(string(raw), private) {
				t.Fatalf("local inventory entered a report projection: %s", raw)
			}
		}
	}
	if _, err := os.Lstat(Home()); !os.IsNotExist(err) {
		t.Fatalf("observing skills wrote state: %v", err)
	}
}

func TestDoctorMalformedPinnedKeysRemainAnErrorAndArePreserved(t *testing.T) {
	for name, malformed := range map[string]string{
		"json": "{broken", "version": `{"version":2,"keys":{}}`, "public_key": `{"version":1,"keys":{"publisher":"not a public key"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			base, _ := doctorFixture(t)
			writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
			if err := os.MkdirAll(Home(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(defaultTrustedKeys(), []byte(malformed), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code := doctorResult(t, runDoctor, "--json")
			if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Verified != 0 || out.Inventory.Errors != 1 || out.NextAction.Code != "inspect_trust" || !reflect.DeepEqual(out.NextCommand, []string{"skillctl", "trust"}) {
				t.Fatalf("malformed trust became absence: %+v, exit %d", out, code)
			}
			body, err := os.ReadFile(defaultTrustedKeys())
			if err != nil || string(body) != malformed {
				t.Fatalf("doctor replaced the malformed pins: %v", err)
			}
			assertDoctorDidNotCreateKeys(t)
		})
	}
}

func TestDoctorBrokenExistingRootIsAnErrorAlongsideReadableSkills(t *testing.T) {
	base, root := doctorFixture(t)
	writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
	broken := filepath.Join(base, "broken")
	if err := os.Symlink(filepath.Join(base, "missing"), broken); err != nil {
		t.Fatal(err)
	}
	setDoctorRoots(t, root, broken, filepath.Join(base, "absent"))
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Unapproved != 1 || out.Inventory.Errors != 1 || !strings.Contains(out.Inventory.Details, "broken") {
		t.Fatalf("broken root became an empty check: %+v, exit %d", out, code)
	}
}

func TestDoctorBrokenChildCannotMakePartialDiscoveryGreen(t *testing.T) {
	base, root := doctorFixture(t)
	skill := writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
	approveDoctorSkill(t, skill, "review")
	if err := os.Symlink(filepath.Join(base, "missing-target"), filepath.Join(root, "broken-child")); err != nil {
		t.Fatal(err)
	}
	for _, run := range []func([]string) int{
		runDoctor,
		func(args []string) int { return runStatus(append(args, "--refresh")) },
	} {
		out, code := doctorResult(t, run, "--json")
		if code != exitFindings || out.Status != "needs_attention" || out.Inventory.Found != 1 || out.Inventory.Verified != 1 || out.Inventory.Errors != 1 || !strings.Contains(out.Inventory.Details, "broken-child") {
			t.Fatalf("incomplete discovery borrowed green from a verified skill: %+v, exit %d", out, code)
		}
	}
	assertDoctorDidNotCreateKeys(t)
}

func TestDoctorUnreadableApprovalStoreDoesNotHideInstalledSkills(t *testing.T) {
	base, _ := doctorFixture(t)
	writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homePath(attest.StoreDirectory), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Errors != 1 || out.Inventory.Verified != 0 || !strings.Contains(out.Inventory.Details, attest.StoreDirectory) {
		t.Fatalf("unreadable approvals hid the installed inventory: %+v, exit %d", out, code)
	}
	assertDoctorDidNotCreateKeys(t)
}

func TestDoctorMalformedSiblingApprovalIsAnError(t *testing.T) {
	for name, body := range map[string]string{"json": "{broken", "envelope": `{}`} {
		t.Run(name, func(t *testing.T) {
			base, _ := doctorFixture(t)
			skill := writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
			path := attest.DefaultName(skill)
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			out, code := doctorResult(t, runDoctor, "--json")
			if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Verified != 0 || out.Inventory.Errors != 1 || !strings.Contains(out.Inventory.Details, "review.att.json") {
				t.Fatalf("malformed sibling silently became unapproved: %+v, exit %d", out, code)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != body {
				t.Fatalf("doctor replaced a damaged approval: %v", err)
			}
			assertDoctorDidNotCreateKeys(t)
		})
	}
}

func TestDoctorUntrustedSiblingStillRequiresAnExplicitTrustDecision(t *testing.T) {
	base, _ := doctorFixture(t)
	skill := writeSkill(t, base, "review", "---\nname: review\ndescription: example\n---\nReview.\n")
	approval := approveDoctorSkill(t, skill, "review")
	if err := os.Rename(approval, attest.DefaultName(skill)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(defaultTrustedKeys()); err != nil {
		t.Fatal(err)
	}
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.Inventory.Found != 1 || out.Inventory.Verified != 0 || out.Inventory.Unapproved != 1 || out.Inventory.Errors != 0 || out.Inventory.TrustedKeys != 0 {
		t.Fatalf("an untrusted sibling changed the trust decision: %+v, exit %d", out, code)
	}
	if _, err := os.Lstat(defaultTrustedKeys()); !os.IsNotExist(err) {
		t.Fatalf("doctor pinned the unknown publisher: %v", err)
	}
	assertDoctorDidNotCreateKeys(t)
}

func TestDoctorConfiguredMachineUsesManagedStatusRefresh(t *testing.T) {
	_, client := localStatusFixture(t)
	previous := doctorRootCandidates
	doctorRootCandidates = func() []string { t.Fatal("configured machine used the cold inventory path"); return nil }
	t.Cleanup(func() { doctorRootCandidates = previous })
	out, code := doctorResult(t, runDoctor, "--json")
	if code != exitClean || out.Status != "local_checked" || out.Inventory != nil || out.LastCheck == nil || out.LastCheck.Checked != 1 || out.ReportAccepted {
		t.Fatalf("managed check changed behavior: %+v, exit %d", out, code)
	}
	if code := tamperDemoPlugin(client); code != exitClean {
		t.Fatalf("tamper fixture: %d", code)
	}
	out, code = doctorResult(t, runDoctor, "--json")
	if code != exitFindings || out.LastCheck.Changed != 1 || out.Inventory != nil {
		t.Fatalf("managed changed bytes passed: %+v, exit %d", out, code)
	}
	body, err := os.ReadFile(filepath.Join(client, "plugins", "cache", "acme", "deploy-runbook", "1.0.0", "SKILL.md"))
	if err != nil || !strings.Contains(string(body), demoTamper) {
		t.Fatalf("doctor restored an installed plugin: %v", err)
	}
}
