package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
)

// runStatusline reads existing local evidence. It neither refreshes checks nor
// modifies the client's statusLine; owners can compose it with their existing one.
func runStatusline(args []string) int {
	flags := flag.NewFlagSet("statusline", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s statusline\n\n"+
			"Prints a short marker from the last local check and preserved edits.\n"+
			"Never contacts a service or creates keys. Append it to your existing\n"+
			"status-line script; this command does not change client settings.\n", commandName())
	}
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return exitUsage
	}
	now := time.Now().UTC()
	pending, err := marketplace.PendingQuarantines(quarantineRoot())
	status := inspectMachine(now)
	if check, checkErr := statuslineLooseCheck(now); checkErr != nil {
		status.Status = "needs_attention"
		status.LastCheck = nil
	} else if check != nil && !check.HealthyAt(now) {
		status.Status, status.LastCheck = "needs_attention", check
	}
	fmt.Fprintln(os.Stdout, statuslineText(status, pending, err, now))
	return exitClean
}

func statuslineText(status machineStatus, pending int, quarantineErr error, now time.Time) string {
	next := commandName() + " doctor"
	if quarantineErr != nil {
		return "Axela: saved edits need attention | " + next
	}
	if pending > 0 {
		return fmt.Sprintf("Axela: edits saved (%d) | %s", pending, next)
	}
	if status.LastCheck != nil && status.LastCheck.Changed > 0 {
		return fmt.Sprintf("Axela: changed (%d) | %s", status.LastCheck.Changed, next)
	}
	if status.LastCheck != nil && status.LastCheck.HealthyAt(now) &&
		(status.Status == "connected" || status.Status == "local_checked") {
		return "Axela: last managed check passed"
	}
	if status.Status == "needs_attention" {
		return "Axela: needs attention | " + next
	}
	return "Axela: unchecked | " + next
}

// A managed report cannot hide an existing loose-skill report with changed bytes.
// Its absence is allowed because machines need not have any approved loose skills.
func statuslineLooseCheck(now time.Time) (*report.CheckResult, error) {
	path := latestCheckPath(CheckScopeApprovedSkills)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	public, err := reportingPublicKey()
	if err != nil {
		return nil, err
	}
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		return nil, err
	}
	check, _, err := report.VerifyCheck(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		return nil, err
	}
	config, err := report.LoadConfig(reportConfigPath())
	if err != nil {
		return nil, err
	}
	if check.Scope != CheckScopeApprovedSkills || check.Machine != machineName(config) ||
		check.CheckedAt.After(now.Add(5*time.Minute)) {
		return nil, fmt.Errorf("the cached loose-skill check does not describe this machine")
	}
	check.FreshUntil = clampCheckFreshness(check.FreshUntil, check.CheckedAt)
	return check, nil
}
