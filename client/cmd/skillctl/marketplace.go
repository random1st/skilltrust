package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/catalog"
	"github.com/random1st/skilltrust/client/internal/marketplace"
)

const marketplaceUsage = `Usage: skillctl marketplace <subcommand> [flags]

  sign    sign the plugins a Claude Code marketplace repository owns
  verify  check installed plugins against the marketplace's signature

`

func runMarketplace(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, marketplaceUsage)
		return exitUsage
	}
	switch args[0] {
	case "sign":
		return runMarketplaceSign(args[1:])
	case "verify":
		return runMarketplaceVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown marketplace subcommand %q\n\n%s", args[0], marketplaceUsage)
		return exitUsage
	}
}

// runMarketplaceSign signs what a Claude Code marketplace already publishes.
//
// The catalog is not a second file an organisation has to maintain: it is their existing
// marketplace.json, digested plugin by plugin and signed beside it. A separate catalog would
// drift from the real one, and the drift would be invisible until the day it mattered.
func runMarketplaceSign(args []string) int {
	flags := flag.NewFlagSet("marketplace sign", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl marketplace sign [flags] [repository]\n\n"+
			"Digests every plugin the marketplace owns and signs the result into %s,\n"+
			"beside the marketplace it describes. Plugins hosted elsewhere are reported,\n"+
			"not signed: their bytes come from somewhere this publisher does not control.\n\n"+
			"Exit codes: %d signed, %d error.\n\nFlags:\n",
			CatalogFileName, exitClean, exitUsage)
		flags.PrintDefaults()
	}

	keyPath := flags.String("key", defaultSigningKey(), "signing key")
	validFor := flags.Duration("valid-for", 7*24*time.Hour,
		"how long consumers may keep using this signature before refreshing")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	repository := flags.Arg(0)
	if repository == "" {
		repository = "."
	}
	repository, err := filepath.Abs(repository)
	if err != nil {
		return fail(err)
	}

	manifest, err := marketplace.Load(repository)
	if err != nil {
		return fail(err)
	}
	coverage, err := marketplace.Plan(repository, manifest)
	if err != nil {
		return fail(err)
	}
	if len(coverage.Signed) == 0 {
		fmt.Fprintf(os.Stderr, "skillctl: %s owns no plugins this key can sign\n", manifest.Name)
		return exitUsage
	}

	key, err := attest.LoadPrivateKey(*keyPath)
	if err != nil {
		return fail(err)
	}

	now := time.Now().UTC()
	snapshot := catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: manifest.Name, Sequence: 1,
		IssuedAt: now, ValidUntil: now.Add(*validFor), Skills: coverage.Signed,
	}

	indexPath := filepath.Join(repository, CatalogFileName)
	if existing, err := attest.LoadEnvelope(indexPath); err == nil {
		previous, _, err := catalog.Open(existing,
			attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)))
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"skillctl: refusing to replace a signature this key cannot verify: %v\n", err)
			return exitUsage
		}
		snapshot.Sequence = previous.Sequence + 1
		snapshot.Revoked = previous.Revoked
	} else if !os.IsNotExist(err) {
		return fail(err)
	}

	envelope, err := catalog.Sign(snapshot, key)
	if err != nil {
		return fail(err)
	}
	if err := envelope.Save(indexPath); err != nil {
		return fail(err)
	}

	fmt.Printf("marketplace %s\n", manifest.Name)
	fmt.Printf("signature   %s\n", indexPath)
	fmt.Printf("sequence    %d\n", snapshot.Sequence)
	fmt.Printf("signed      %d of %d plugin%s\n\n",
		len(coverage.Signed), len(manifest.Plugins), plural(len(manifest.Plugins), "", "s"))
	for _, managed := range coverage.Signed {
		fmt.Printf("  %s  %-28s %s\n", shortDigest(managed.Digest), managed.Name, managed.Version)
	}
	reportCoverage(coverage)
	fmt.Printf("\nCommit %s so machines can check what they installed.\n", CatalogFileName)
	return exitClean
}

// reportCoverage names what a signature does not cover, on the screen rather than in a
// footnote. A publisher who believes they signed 169 plugins when they signed 49 has been
// misled by their own tool.
func reportCoverage(coverage *marketplace.Coverage) {
	if len(coverage.Partial) > 0 {
		fmt.Printf("\n  partially covered — dependency code was installed after fetch and is\n")
		fmt.Printf("  outside the signature; vendor dependencies for full coverage:\n")
		for _, name := range coverage.Partial {
			fmt.Printf("    %s\n", name)
		}
	}
	if len(coverage.Unversioned) > 0 {
		fmt.Printf("\n  not signed — no version, so the installed directory cannot be named:\n")
		for _, name := range coverage.Unversioned {
			fmt.Printf("    %s\n", name)
		}
	}
	for kind, names := range coverage.Remote {
		fmt.Printf("\n  not signed — %d plugin%s hosted elsewhere (%s); this publisher does\n",
			len(names), plural(len(names), "", "s"), kind)
		fmt.Printf("  not control those bytes and cannot vouch for them\n")
	}
}

// installedStatus is the verdict for one plugin the marketplace signed.
type installedStatus struct {
	name, version, expected, actual, detail string
	ok                                      bool
}

// runMarketplaceVerify checks what Claude Code actually installed against what was signed.
//
// The plugin cache is the artifact that matters and the one nobody looks at twice: Claude
// Code copies a plugin there at install time and never returns to it, while an agent with
// write access can edit it at any point afterwards. Verifying the marketplace repository
// instead would check bytes nobody runs.
func runMarketplaceVerify(args []string) int {
	flags := flag.NewFlagSet("marketplace verify", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl marketplace verify [flags]\n\n"+
			"Compares the plugins Claude Code installed against the marketplace signature.\n"+
			"Reads %s from the marketplace checkout and the installed copies from the\n"+
			"plugin cache.\n\n"+
			"Exit codes: %d as signed, %d something differs, %d error.\n\nFlags:\n",
			CatalogFileName, exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	repo := flags.String("repo", "", "marketplace checkout to read the signature from")
	keyPath := flags.String("key", "", "public key the signature must carry (required with --repo)")
	claudeHome := flags.String("claude-home", "", "Claude Code directory (default ~/.claude)")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	home := *claudeHome
	if home == "" {
		home = marketplace.DefaultClaudeHome()
	}

	snapshots, code := marketplaceSnapshots(*repo, *keyPath)
	if code != exitClean {
		return code
	}

	problems := 0
	for name, snapshot := range snapshots {
		fmt.Printf("%s   sequence %d\n", name, snapshot.Sequence)
		for _, managed := range snapshot.Skills {
			status := checkInstalled(home, name, managed, snapshot)
			if !status.ok {
				problems++
			}
			switch {
			case status.ok:
				fmt.Printf("  ok          %-28s %s\n", status.name, status.version)
			default:
				fmt.Printf("  %-11s %-28s %s\n", status.detail, status.name, status.version)
				if status.expected != "" && status.actual != "" {
					fmt.Printf("              signed   %s\n", status.expected)
					fmt.Printf("              on disk  %s\n", status.actual)
				}
			}
		}
		fmt.Println()
	}

	if problems > 0 {
		fmt.Printf("%d plugin%s %s from what was signed.\n",
			problems, plural(problems, "", "s"), plural(problems, "differs", "differ"))
		return exitFindings
	}
	fmt.Printf("Every signed plugin is installed as signed.\n")
	return exitClean
}

// checkInstalled compares one installed plugin against its signature.
func checkInstalled(
	claudeHome, marketplaceName string, managed catalog.Managed, snapshot *catalog.Snapshot,
) installedStatus {
	status := installedStatus{name: managed.Name, version: managed.Version, expected: managed.Digest}

	if entry, revoked := snapshot.IsRevoked(managed.Digest); revoked {
		status.detail = "revoked"
		if entry.Reason != "" {
			status.detail = "revoked"
			status.name = managed.Name + " — " + entry.Reason
		}
		return status
	}

	directory := marketplace.InstalledPath(claudeHome, marketplaceName, managed.Name, managed.Version)
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		// Not installed is not drift. Reporting it as a problem would make every machine
		// that chose a subset of the catalog look compromised.
		if others := marketplace.InstalledVersions(claudeHome, marketplaceName, managed.Name); len(others) > 0 {
			status.detail = "wrong ver"
			status.version = managed.Version + " signed, " + others[0] + " installed"
			return status
		}
		status.ok = true
		status.version = managed.Version + " (not installed)"
		return status
	}

	digest, _, err := marketplace.DigestPlugin(directory)
	if err != nil {
		status.detail = "unreadable"
		return status
	}
	status.actual = digest
	if digest == managed.Digest {
		status.ok = true
		return status
	}
	status.detail = "changed"
	return status
}

// marketplaceSnapshots resolves which signatures to check, from an explicit checkout or from
// the catalogs this machine follows.
func marketplaceSnapshots(repo, keyPath string) (map[string]*catalog.Snapshot, int) {
	snapshots := map[string]*catalog.Snapshot{}

	if repo != "" {
		if keyPath == "" {
			fmt.Fprintln(os.Stderr, "skillctl: --repo needs --key; a signature checked "+
				"against no particular key is not a check")
			return nil, exitUsage
		}
		public, err := attest.LoadPublicKey(keyPath)
		if err != nil {
			return nil, fail(err)
		}
		envelope, err := attest.LoadEnvelope(filepath.Join(repo, CatalogFileName))
		if err != nil {
			return nil, fail(err)
		}
		snapshot, _, err := catalog.Verify(envelope,
			attest.NewTrustedKeys(public), nil, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: the signature did not verify: %v\n", err)
			return nil, exitFindings
		}
		snapshots[snapshot.Name] = snapshot
		return snapshots, exitClean
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return nil, fail(err)
	}
	if len(subscriptions) == 0 {
		fmt.Fprintln(os.Stderr, "skillctl: no marketplaces followed; pass --repo and --key, "+
			"or subscribe with `skillctl subscribe <git-url> --key <publisher.pub>`")
		return nil, exitUsage
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return nil, fail(err)
	}
	now := time.Now().UTC()
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: %s could not be verified: %v\n",
				subscription.Name, err)
			return nil, exitFindings
		}
		snapshots[snapshot.Name] = snapshot
	}
	return snapshots, exitClean
}
