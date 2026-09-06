package main

import (
	"flag"
	"fmt"
)

// Installation is an explicit action. Doctor only recommends it after observing
// empty coverage; the existing native installer verifies and freezes the payload.
func runInstall(args []string) int {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	client := flags.String("client", "claude", "native client to install into (currently claude)")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s install [--client claude]\n\n"+
			"Install the first available signed plugin from a followed catalog.\n"+
			"Uses the native client and a verified copy of the published bytes.\n"+
			"Existing installed plugins are checked without replacing local changes.\n\nFlags:\n", commandName())
		flags.PrintDefaults()
	}
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		return fail(fmt.Errorf("install takes no positional arguments; use subscribe to choose a publisher"))
	}
	known, err := lookupAgent(*client)
	if err != nil {
		return fail(err)
	}
	if err := ensureFirstManagedPlugin(known); err != nil {
		return fail(err)
	}
	// Native exit zero alone is insufficient: inspect what is actually installed.
	return runDoctor(nil)
}
