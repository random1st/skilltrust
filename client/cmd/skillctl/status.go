package main

import (
	"encoding/json"
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
	Version        int                 `json:"version"`
	Status         string              `json:"status"`
	Title          string              `json:"title"`
	NextAction     *nextAction         `json:"next_action,omitempty"`
	ServiceURL     string              `json:"service_url,omitempty"`
	Organisation   string              `json:"organisation,omitempty"`
	Machine        string              `json:"machine,omitempty"`
	DashboardURL   string              `json:"dashboard_url,omitempty"`
	ApprovalURL    string              `json:"approval_url,omitempty"`
	Hooks          []machineHook       `json:"hooks"`
	LastCheck      *report.CheckResult `json:"last_check,omitempty"`
	ReportAccepted bool                `json:"report_accepted"`
	PendingReports int                 `json:"pending_reports"`
}

func latestCheckPath(scope string) string {
	return filepath.Join(Home(), "checks", sanitizeScope(scope)+".json")
}

func latestCheckReceiptPath(scope string) string {
	return filepath.Join(Home(), "checks", sanitizeScope(scope)+".receipt.json")
}

func inspectMachine(now time.Time) machineStatus {
	out := machineStatus{Version: 1, Status: "not_connected", Title: "Connect this computer", Hooks: []machineHook{},
		NextAction: &nextAction{"connect", "user", "Run skillctl connect to choose a team in the browser. Setup continues automatically after approval."}}
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
		if pending != nil {
			out.ServiceURL, out.Machine = pending.Audience, pending.Machine
			out.Status, out.Title = "approval_pending", "Finish connection in the browser"
			out.NextAction = &nextAction{"connect", "user", "Run skillctl connect to resume the saved connection. If approval is still needed, use the browser link it returns."}
			if !pending.Expired {
				out.ApprovalURL, _ = approvalURL(pending.Audience, pending.Envelope)
			}
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
	var refreshErr error
	if *refresh {
		refreshErr = refreshMachineStatus()
	}
	out := inspectMachine(connectNow())
	if refreshErr != nil {
		out.Status, out.Title = "needs_attention", "The current check did not finish"
		out.NextAction = &nextAction{"check_connection", "user", refreshErr.Error()}
	}
	if *asJSON {
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
		if out.NextAction != nil {
			fmt.Printf("Next (%s): %s\n", out.NextAction.Actor, out.NextAction.Detail)
		}
		if out.ApprovalURL != "" {
			fmt.Printf("Approval: %s\n", out.ApprovalURL)
		}
		for _, hook := range out.Hooks {
			if hook.ApprovalRequired {
				fmt.Println("Codex: its own hook approval is still required if prompted.")
			}
		}
	}
	if out.Status != "connected" {
		return exitFindings
	}
	return exitClean
}

func refreshMachineStatus() error {
	current, err := loadSavedConnect()
	if err != nil || current == nil {
		return fmt.Errorf("Run skillctl connect to finish connecting this computer first.")
	}
	agent, ok := preferredManagedAgent(detectManagedAgents())
	if !ok {
		return fmt.Errorf("Open Claude Code or Codex, then run skillctl connect.")
	}
	managed, code := RunManagedCheck(agent.Home(), ManagedCheckOptions{Offline: false, UpdateSource: true, RefreshBudget: 3 * time.Second})
	if code != exitClean {
		return fmt.Errorf("The installed skills could not be checked. Run skillctl connect to diagnose the setup.")
	}
	check := managedCurrentCheck(aggregateManagedReportCheck(managed, agent.Home(), agent.Name, ""))
	_, err = recordCurrentChecks(time.Duration(reportTimeoutSeconds)*time.Second, check)
	if err != nil {
		return fmt.Errorf("The check ran, but its report could not be delivered. Run skillctl report flush.")
	}
	return nil
}
