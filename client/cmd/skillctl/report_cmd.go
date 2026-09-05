package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func runReport(args []string) int {
	if len(args) == 0 || args[0] != "flush" {
		fmt.Fprintln(os.Stderr, "Usage: skillctl report flush [-timeout 2s]\n\nRetries saved reports and shows what still needs to be delivered.")
		if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
			return exitClean
		}
		return exitUsage
	}
	flags := flag.NewFlagSet("report flush", flag.ContinueOnError)
	timeout := flags.Duration("timeout", 2*time.Second, "total time allowed for delivery")
	if err := parseArgs(flags, args[1:]); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *timeout <= 0 || *timeout > time.Minute {
		fmt.Fprintln(os.Stderr, "skillctl: report flush takes no paths; -timeout must be greater than zero and at most 1m")
		return exitUsage
	}
	status, err := FlushPendingEventReports(*timeout)
	fmt.Printf("delivered   %d events, %d checks\n", status.DeliveredEvents, status.DeliveredChecks)
	fmt.Printf("pending     %d events, %d checks\n", status.PendingEvents, status.PendingChecks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: reports remain saved for retry: %v\n", err)
		return exitFindings
	}
	if status.PendingEvents > 0 || status.PendingChecks > 0 {
		return exitFindings
	}
	return exitClean
}
