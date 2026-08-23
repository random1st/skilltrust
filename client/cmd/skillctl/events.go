package main

import (
	"fmt"
	"os"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/marketplace"
	"github.com/random1st/skilltrust/client/internal/report"
)

func reportConfigPath() string { return homePath("reporting.json") }
func spool() report.Spool      { return report.Spool{Directory: homePath("events")} }

// machineName identifies this machine in a report. The hostname is the name whoever reads an
// alert already knows the machine by; a generated identifier would be correct and useless.
func machineName(config *report.Config) string {
	if config != nil && config.Machine != "" {
		return config.Machine
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "unknown"
}

// recordEvents turns a reconciliation into signed events and tries to deliver them.
//
// It is called after the work is done and never before: an event is a report of something
// that already happened, so a failure to sign or send can delay the telling but can never
// change what was done. That ordering is why reporting can be best-effort without the check
// becoming best-effort too.
func recordEvents(results []marketplace.Result, unusable []string, now time.Time) {
	events := collectEvents(results, unusable, now)
	if len(events) == 0 {
		return
	}

	config, err := report.LoadConfig(reportConfigPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: reporting is misconfigured, so nothing was "+
			"reported: %v\n", err)
		return
	}
	key, err := attest.LoadPrivateKey(defaultSigningKey())
	if err != nil {
		// Without a key an event cannot be attributed, and an unattributable report in a
		// console is worse than none: it looks like evidence and names nobody.
		fmt.Fprintf(os.Stderr, "skillctl: no machine key, so %d event%s could not be "+
			"reported; run `skillctl init`\n", len(events), plural(len(events), "", "s"))
		return
	}

	name := machineName(config)
	for _, event := range events {
		event.Machine = name
		event.Host = name
		event.Complete()

		envelope, err := report.Sign(event, key)
		if err != nil {
			continue
		}
		path, err := spool().Add(envelope, event.At, string(event.Kind))
		if err != nil {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := report.Deliver(config, event, body, config.Timeout); err != nil {
			// Kept in the spool rather than dropped: the one incident worth hearing about
			// is disproportionately likely to be the one that happened while the network
			// was unreachable.
			continue
		}
		_ = os.Remove(path)
	}
}

// collectEvents keeps only what is worth waking someone for. An unchanged plugin produces
// nothing, because a stream that reports normality is a stream nobody reads.
func collectEvents(results []marketplace.Result, unusable []string, now time.Time) []report.Event {
	var events []report.Event

	for _, result := range results {
		kind, ok := kindFor(result.Outcome)
		if !ok {
			continue
		}
		events = append(events, report.Event{
			Kind: kind, At: now,
			Marketplace: result.Marketplace, Plugin: result.Plugin, PluginVer: result.Version,
			Signed: result.Signed, Found: result.OnDisk,
			Quarantine: result.Quarantine, Detail: result.Detail,
		})
	}
	for _, failure := range unusable {
		events = append(events, report.Event{
			Kind: report.KindCatalogUnusable, At: now, Detail: failure,
		})
	}
	return events
}

func kindFor(outcome marketplace.Outcome) (report.Kind, bool) {
	switch outcome {
	case marketplace.OutcomeRestored:
		return report.KindRestored, true
	case marketplace.OutcomeRevoked:
		return report.KindRevoked, true
	case marketplace.OutcomeChanged, marketplace.OutcomeUnverifiable:
		return report.KindUnverifiable, true
	default:
		return "", false
	}
}
