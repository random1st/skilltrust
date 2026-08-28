// Command skilltrust-mcp serves SkillTrust to an agent over the Model Context Protocol, so
// setting a machine up is something the agent does rather than something a person copies out
// of a README.
//
// It is a second binary rather than a skillctl subcommand. skillctl decides whether a skill
// is trusted and runs on every session start; the MCP SDK brings nine dependencies with it,
// and a verifier whose supply chain grows to serve a convenience is arguing against itself.
// Go links per package, so this arrangement keeps skillctl's linked set at two.
//
//	skilltrust-mcp            serve over stdio
//	skilltrust-mcp -version   print version information
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed setup.md
var setupGuide string

// version is set at build time; see the Makefile.
var version = "dev"

type server struct {
	run  runner
	home string
}

func main() {
	showVersion := flag.Bool("version", false, "print version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("skilltrust-mcp %s\n", version)
		return
	}

	if err := serve(); err != nil {
		fmt.Fprintf(os.Stderr, "skilltrust-mcp: %v\n", err)
		os.Exit(1)
	}
}

func serve() error {
	binary, err := findSkillctl()
	if err != nil {
		return err
	}

	s := &server{run: runner{binary: binary}, home: skilltrustHome()}
	s.run.home = s.home

	m := mcp.NewServer(&mcp.Implementation{
		Name:    "skilltrust",
		Title:   "SkillTrust",
		Version: version,
	}, &mcp.ServerOptions{
		// Read skilltrust://state first, and read the guide before deciding an order. Said
		// here because a client shows these instructions once, before any tool is called,
		// which is the only moment early enough to matter.
		Instructions: "SkillTrust proves who published a skill's bytes and that they have " +
			"not changed. It does not prove a skill is safe, and does not inspect what one " +
			"does. Read skilltrust://state before acting: it reports what is already set up " +
			"and names the next step. The steps are order-dependent and every one of them " +
			"succeeds out of order, so use the set_up_this_machine prompt rather than " +
			"calling tools in the order they are listed.",
	})

	s.addResources(m)
	s.addPrompts(m)
	s.addTools(m)

	// Stop on interrupt so a client that closes the connection does not leave the process
	// holding a terminal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := m.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func sortStrings(values []string) { sort.Strings(values) }

func firstLine(text string) string {
	for index, character := range text {
		if character == '\n' {
			return text[:index]
		}
	}
	return text
}
