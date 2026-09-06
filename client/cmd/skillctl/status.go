package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/report"
)

type nextAction struct {
	Code   string `json:"code"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}

type machineHook struct {
	Agent            string `json:"agent"`
	Installed        bool   `json:"installed"`
	ApprovalRequired bool   `json:"approval_required,omitempty"`
}

// machineStatus is a public projection, never a serialization of enrollment or
// reporting configuration. Those files include credentials.
type machineStatus struct {
	Version           int                 `json:"version"`
	Status            string              `json:"status"`
	Title             string              `json:"title"`
	NextAction        *nextAction         `json:"next_action,omitempty"`
	NextCommand       []string            `json:"next_command,omitempty"`
	Inventory         *skillInventory     `json:"inventory,omitempty"`
	SavedChanges      []savedSkillChange  `json:"saved_changes,omitempty"`
	SavedChangesError string              `json:"saved_changes_error,omitempty"`
	ServiceURL        string              `json:"service_url,omitempty"`
	Organisation      string              `json:"organisation,omitempty"`
	Machine           string              `json:"machine,omitempty"`
	DashboardURL      string              `json:"dashboard_url,omitempty"`
	ApprovalURL       string              `json:"approval_url,omitempty"`
	Hooks             []machineHook       `json:"hooks"`
	LastCheck         *report.CheckResult `json:"last_check,omitempty"`
	ReportAccepted    bool                `json:"report_accepted"`
	PendingReports    int                 `json:"pending_reports"`
}

func latestCheckPath(scope string) string {
	return filepath.Join(Home(), "checks", sanitizeScope(scope)+".json")
}

func latestCheckReceiptPath(scope string) string {
	return filepath.Join(Home(), "checks", sanitizeScope(scope)+".receipt.json")
}

func inspectMachine(now time.Time) machineStatus {
	out := machineStatus{Version: 1, Status: "not_connected", Title: "Choose signed skills to follow", Hooks: []machineHook{},
		NextAction: &nextAction{"subscribe", "user", "Follow a publisher without an account: run skillctl subscribe with their repository and public key. If you are joining an Axela team, use skillctl connect."}}
	attention := func(code, actor, detail string) machineStatus {
		out.Status, out.Title = "needs_attention", "Needs attention"
		out.NextAction = &nextAction{code, actor, detail}
		return out
	}
	current, err := loadSavedConnect()
	if err != nil {
		return attention("repair_connection", "user", "The saved connection could not be read. Run skillctl connect to diagnose it; keep the existing machine key.")
	}
	if current == nil {
		pending, err := loadPendingConnect(now)
		if err != nil {
			return attention("repair_connection", "user", "The pending connection could not be read. Run skillctl connect to diagnose it; keep the existing machine key.")
		}
		subscriptions, err := loadSubscriptions()
		if err != nil {
			return attention("check_skills", "user", "The followed catalogs could not be read. Run skillctl sync --report-only to diagnose them; keep the existing keys.")
		}
		if len(subscriptions) > 0 {
			local := inspectLocalMachine(now, subscriptions)
			if pending != nil && !pending.Expired {
				local.ApprovalURL, _ = approvalURL(pending.Audience, pending.Envelope)
			}
			return local
		}
		if pending != nil {
			out.ServiceURL, out.Machine = pending.Audience, pending.Machine
			out.Status, out.Title = "approval_pending", "Finish connection in the browser"
			out.NextAction = &nextAction{"connect", "user", "Run skillctl connect to resume the saved connection. If approval is still needed, use the browser link it returns."}
			if !pending.Expired {
				out.ApprovalURL, _ = approvalURL(pending.Audience, pending.Envelope)
			}
			return out
		}
		return out
	}
	out.ServiceURL, out.Organisation, out.Machine, out.DashboardURL = current.Audience, current.Organisation, current.Machine, current.DashboardURL
	if current.Version != connectRecordVersion {
		return attention("upgrade_client", "user", "Update SkillTrust to read this connection.")
	}
	public, err := reportingPublicKey()
	if err != nil || attest.KeyID(public) != current.MachineKeyID {
		return attention("repair_connection", "user", "The saved connection does not match this machine's signing key. Run skillctl connect to diagnose it; do not replace the key.")
	}
	if current.IdentityOnly {
		subscriptions, err := loadSubscriptions()
		if err != nil {
			return attention("check_skills", "user", "The followed catalogs could not be read; run skillctl doctor to diagnose them.")
		}
		local := inspectLocalMachine(now, subscriptions)
		local.ServiceURL, local.Organisation, local.Machine = current.Audience, current.Organisation, current.Machine
		return local
	}
	for _, agent := range detectManagedAgents() {
		out.Hooks = append(out.Hooks, machineHook{Agent: agent.Name, Installed: hookInstalled(agent), ApprovalRequired: agent.Name == "codex"})
	}
	if pending, err := pendingReportStatus(); err == nil {
		out.PendingReports = pending.PendingChecks + pending.PendingEvents
	} else {
		return attention("check_reports", "user", "The saved report queue could not be read. Run skillctl report flush to diagnose delivery.")
	}
	path := latestCheckPath(CheckScopeManaged)
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		return attention("check_connection", "user", "Run skillctl status --refresh to check installed skills and confirm report delivery.")
	}
	check, signer, err := report.VerifyCheck(envelope, attest.NewTrustedKeys(public))
	if err != nil || check.Scope != CheckScopeManaged || check.Machine != current.Machine || check.CheckedAt.After(now.Add(5*time.Minute)) {
		return attention("check_connection", "user", "The last check could not be verified for this computer. Run skillctl status --refresh.")
	}
	out.LastCheck = check
	body, err := os.ReadFile(path)
	var receipt connectStatusFile
	raw, readErr := os.ReadFile(latestCheckReceiptPath(CheckScopeManaged))
	if os.IsNotExist(readErr) {
		raw, readErr = os.ReadFile(connectStatusPath())
	}
	if err == nil && readErr == nil && json.Unmarshal(raw, &receipt) == nil {
		acceptedAt, parseErr := time.Parse(time.RFC3339, receipt.AcceptedAt)
		out.ReportAccepted = receipt.Version == connectStatusVersion && receipt.Signer == signer && receipt.Digest == digestHex(body) &&
			receipt.AcceptedURL == current.IngestURL && parseErr == nil && !acceptedAt.Before(check.CheckedAt.Add(-5*time.Minute)) && !acceptedAt.After(now.Add(5*time.Minute))
	}
	for _, c := range check.Catalogs {
		if !c.ValidUntil.IsZero() && !now.Before(c.ValidUntil) {
			return attention("renew_catalog", "publisher", fmt.Sprintf("The publisher needs to renew %s with the existing signing key. Run skillctl publish --renew in its repository, then submit and verify the renewal.", c.Name))
		}
	}
	if !check.HealthyAt(now) {
		return attention("check_connection", "user", "The last check needs attention or has expired. Run skillctl status --refresh; review changed skills before restoring them.")
	}
	if !out.ReportAccepted || out.PendingReports > 0 {
		return attention("retry_reports", "user", "Run skillctl report flush to retry delivery, then skillctl status --refresh if the check is no longer current.")
	}
	if len(out.Hooks) == 0 {
		return attention("connect", "user", "Open Claude Code or Codex on this computer, then run skillctl connect to finish automatic checks.")
	}
	for _, hook := range out.Hooks {
		if !hook.Installed {
			return attention("connect", "user", "Run skillctl connect to finish installing the session checks.")
		}
	}
	out.Status, out.Title, out.NextAction = "connected", "Last check passed; Axela received the report", nil
	for _, c := range check.Catalogs {
		if !c.ValidUntil.IsZero() && !c.ValidUntil.After(now.Add(catalog.RenewalWindow)) {
			out.NextAction = &nextAction{"renew_catalog", "publisher", fmt.Sprintf("%s expires within 24 hours. Its publisher should run skillctl publish --renew, review and submit the renewal.", c.Name)}
			break
		}
	}
	return out
}

// Local verification has the same signature, freshness and coverage requirements,
// but a hosted enrollment and receipt are not prerequisites for following a publisher.
func inspectLocalMachine(now time.Time, subscriptions []Subscription) machineStatus {
	out := machineStatus{Version: 1, Status: "needs_attention", Title: "Check followed skills locally", Hooks: []machineHook{}}
	attention := func(code, actor, detail string) machineStatus {
		out.NextAction = &nextAction{code, actor, detail}
		return out
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return attention("check_skills", "user", "The pinned publisher keys could not be read. Run skillctl sync --report-only to diagnose them; keep the existing keys.")
	}
	expected := make(map[string]*catalog.Snapshot, len(subscriptions))
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, now)
		if errors.Is(err, catalog.ErrExpired) {
			return attention("renew_catalog", "publisher", fmt.Sprintf("%s has expired. Its publisher must renew it with the existing signing key. After renewal, run skillctl status --refresh.", subscription.Name))
		}
		if err != nil {
			return attention("check_skills", "user", fmt.Sprintf("%s could not be verified: %v. Run skillctl sync --report-only to diagnose this catalog.", subscription.Name, err))
		}
		expected[subscription.Name] = snapshot
	}
	public, err := reportingPublicKey()
	if err != nil {
		return attention("check_skills", "user", "The local check's signing key could not be read. Run skillctl sync --report-only; keep the existing machine key.")
	}
	envelope, err := attest.LoadEnvelope(latestCheckPath(CheckScopeManaged))
	if err != nil {
		return attention("check_skills", "user", "Run skillctl status --refresh to check installed skills locally. A subscription alone does not mean a skill was checked.")
	}
	check, _, err := report.VerifyCheck(envelope, attest.NewTrustedKeys(public))
	config, configErr := report.LoadConfig(reportConfigPath())
	if err != nil || configErr != nil || check.Scope != CheckScopeManaged || check.Machine != machineName(config) || check.CheckedAt.After(now.Add(5*time.Minute)) {
		return attention("check_skills", "user", "The last local check could not be verified for this computer. Run skillctl status --refresh.")
	}
	out.LastCheck = check
	if len(check.Catalogs) != len(expected) {
		return attention("check_skills", "user", "The followed catalogs changed since the last check. Run skillctl status --refresh.")
	}
	for _, checked := range check.Catalogs {
		snapshot := expected[checked.Name]
		if snapshot == nil || checked.Sequence != snapshot.Sequence || !checked.ValidUntil.Equal(snapshot.ValidUntil) {
			return attention("check_skills", "user", "The followed catalog changed since the last check. Run skillctl status --refresh.")
		}
		delete(expected, checked.Name)
	}
	if check.Checked == 0 {
		return attention("install_plugin", "user", "No installed plugin was checked. Install one from a followed publisher using your agent's native plugin command, then run skillctl status --refresh.")
	}
	if !check.HealthyAt(now) {
		return attention("check_skills", "user", "The local check needs attention or has expired. Run skillctl sync --report-only and review changed skills before restoring them.")
	}
	for _, known := range detectManagedAgents() {
		out.Hooks = append(out.Hooks, machineHook{Agent: known.Name, Installed: hookInstalled(known), ApprovalRequired: known.Name == "codex"})
	}
	if len(out.Hooks) == 0 {
		return attention("install_hooks", "user", "Open your supported agent, then run skillctl hook install --apply to check before each session.")
	}
	for _, hook := range out.Hooks {
		if !hook.Installed {
			return attention("install_hooks", "user", fmt.Sprintf("Run skillctl hook install --client %s --apply to check before each session. Approve the hook in your agent if prompted.", hook.Agent))
		}
	}
	out.Status, out.Title = "local_checked", "Last local check passed; session checks are installed"
	return out
}

func runStatus(args []string) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := flags.Bool("json", false, "return public machine state as JSON")
	refresh := flags.Bool("refresh", false, "check installed skills and report the result; never restore or install skills")
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		return fail(fmt.Errorf("status takes no positional arguments"))
	}
	return writeMachineStatus(collectMachineStatus(*refresh), *asJSON)
}

func collectMachineStatus(refresh bool) machineStatus {
	var refreshErr error
	if refresh {
		// An optional pending team enrollment does not block checking local skills.
		// Configured machines keep the existing managed check and reporting path.
		current, currentErr := loadSavedConnect()
		subscriptions, subscriptionErr := loadSubscriptions()
		pending, pendingErr := loadPendingConnect(connectNow())
		if currentErr == nil && current == nil && subscriptionErr == nil && len(subscriptions) == 0 && pendingErr == nil {
			out := inspectInstalledSkills(doctorRootCandidates())
			if pending != nil && !pending.Expired {
				out.ApprovalURL, _ = approvalURL(pending.Audience, pending.Envelope)
			}
			return statusWithSavedChanges(out)
		}
		refreshErr = refreshMachineStatus()
	}
	out := inspectMachine(connectNow())
	if refreshErr != nil {
		out.Status, out.Title = "needs_attention", "The current check did not finish"
		out.NextAction = &nextAction{"check_connection", "user", refreshErr.Error()}
		var access *subscriptionAccessFailure
		if errors.As(refreshErr, &access) {
			actor := "user"
			if access.ownerAction {
				actor = "team_owner"
			}
			out.NextAction = &nextAction{"team_access", actor, access.Error()}
			out.NextCommand = []string{commandName(), "subscribe", access.uri}
		}
	}
	return statusWithSavedChanges(statusWithNextCommand(out))
}

// Keep the public command as argv. Prose may describe an action for the publisher;
// the command offered to this computer must never act as that publisher.
func statusWithNextCommand(out machineStatus) machineStatus {
	if out.NextAction == nil || len(out.NextCommand) > 0 {
		return out
	}
	args := []string{"doctor", "--json"}
	switch out.NextAction.Code {
	case "subscribe":
		args = []string{"subscribe", "--help"}
	case "connect", "repair_connection":
		args = []string{"connect"}
	case "check_skills", "check_connection":
		args = []string{"sync", "--report-only"}
	case "check_reports", "retry_reports":
		args = []string{"report", "flush"}
	case "install_plugin":
		args = []string{"install", "--client", "claude"}
	case "install_hooks":
		args = []string{"hook", "install", "--apply"}
		for _, hook := range out.Hooks {
			if !hook.Installed {
				args = []string{"hook", "install", "--client", hook.Agent, "--apply"}
				break
			}
		}
	case "renew_catalog":
		args = []string{"doctor"}
	}
	out.NextCommand = append([]string{commandName()}, args...)
	return out
}

func writeMachineStatus(out machineStatus, asJSON bool) int {
	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
			return fail(err)
		}
	} else {
		fmt.Println(out.Title)
		if out.Organisation != "" {
			fmt.Printf("Team: %s\n", out.Organisation)
		}
		if out.LastCheck != nil {
			fmt.Printf("Checked: %d skills at %s\n", out.LastCheck.Checked, out.LastCheck.CheckedAt.Format(time.RFC3339))
		}
		if inventory := out.Inventory; inventory != nil {
			fmt.Printf("Found: %d · verified: %d · changed: %d · unapproved: %d · errors: %d\n",
				inventory.Found, inventory.Verified, inventory.Changed, inventory.Unapproved, inventory.Errors)
			fmt.Println("Scope: local skill directories and plugin caches; cached versions may be inactive.")
			for _, skill := range inventory.Skills {
				fmt.Printf("  %-10s %q  %q\n", skill.Verdict, skill.Name, skill.Path)
			}
			if inventory.TrustedKeys == 0 {
				fmt.Println("Trust: no usable publisher keys are pinned; there is no trusted approval basis.")
			}
			if inventory.Details != "" {
				fmt.Println(inventory.Details)
			}
		}
		if out.NextAction != nil {
			fmt.Printf("Next (%s): %s\n", out.NextAction.Actor, out.NextAction.Detail)
		}
		for _, change := range out.SavedChanges {
			fmt.Printf("Saved local change: %q at %q\n", change.Plugin, change.Path)
			writeHookCommand(os.Stdout, "review saved change", change.NextCommand)
		}
		if out.SavedChangesError != "" {
			fmt.Printf("Saved changes could not all be identified: %q\n", out.SavedChangesError)
		}
		if len(out.NextCommand) > 0 {
			printNextCommand(out.NextCommand)
		}
		if out.ApprovalURL != "" {
			if out.Status == "approval_pending" {
				fmt.Printf("Approval: %s\n", out.ApprovalURL)
			} else {
				fmt.Printf("Optional team approval: %s\n", out.ApprovalURL)
			}
		}
		for _, hook := range out.Hooks {
			if hook.ApprovalRequired {
				fmt.Println("Codex: its own hook approval is still required if prompted.")
			}
		}
	}
	if out.Status != "connected" && out.Status != "local_checked" && out.Status != "approvals_checked" {
		return exitFindings
	}
	return exitClean
}

func refreshMachineStatus() error {
	current, err := loadSavedConnect()
	if err != nil {
		return fmt.Errorf("Run skillctl connect to finish connecting this computer first.")
	}
	if current == nil {
		pending, err := loadPendingConnect(connectNow())
		if err != nil {
			return fmt.Errorf("The pending connection could not be read. Run skillctl connect to diagnose it; keep the existing machine key.")
		}
		subscriptions, err := loadSubscriptions()
		if err != nil || len(subscriptions) == 0 {
			if pending != nil {
				return fmt.Errorf("Run skillctl connect to resume the pending browser connection, or follow a publisher with skillctl subscribe to continue without a team.")
			}
			return fmt.Errorf("Follow a publisher first with skillctl subscribe and their public key. No account is required; use skillctl connect only if joining an Axela team.")
		}
	}
	agent, ok := preferredManagedAgent(detectManagedAgents())
	if !ok {
		return fmt.Errorf("Open Claude Code or Codex, install a followed plugin, then run skillctl status --refresh.")
	}
	managed, code := RunManagedCheck(agent.Home(), ManagedCheckOptions{Offline: false, UpdateSource: true, RefreshBudget: 3 * time.Second})
	if code != exitClean {
		return fmt.Errorf("The installed skills could not be checked. Run skillctl sync --report-only to diagnose the setup.")
	}
	check := managedCurrentCheck(aggregateManagedReportCheck(managed, agent.Home(), agent.Name, ""))
	_, err = recordCurrentChecks(time.Duration(reportTimeoutSeconds)*time.Second, check)
	if err != nil {
		return fmt.Errorf("The check ran, but its result could not be saved or sent. Run skillctl sync --report-only to diagnose local checks, or skillctl report flush if reporting is configured.")
	}
	if managed.teamAccessError != nil {
		return managed.teamAccessError
	}
	return nil
}
