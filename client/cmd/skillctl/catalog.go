package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/catalog"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/skillmd"
)

const catalogUsage = `Usage: skillctl catalog <subcommand> [flags]

  revoke   add digests to the signed revocation catalog
  show     print a catalog after verifying it

`

func runCatalog(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, catalogUsage)
		return exitUsage
	}
	switch args[0] {
	case "revoke":
		return runCatalogRevoke(args[1:])
	case "show":
		return runCatalogShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown catalog subcommand %q\n\n%s", args[0], catalogUsage)
		return exitUsage
	}
}

func runCatalogRevoke(args []string) int {
	flags := flag.NewFlagSet("catalog revoke", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), "Usage: skillctl catalog revoke [flags] <digest>...\n\n"+
			"Adds digests to the catalog and re-signs it, advancing the sequence number.\n"+
			"Revocation is keyed by digest so it survives the skill being renamed, moved\n"+
			"or copied elsewhere.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	keyPath := flags.String("key", "skilltrust.key", "signing key")
	catalogPath := flags.String("catalog", "catalog.json", "catalog to extend, created if absent")
	trustedPath := flags.String("trusted-keys", "trusted-keys.json", "pinned keys, to read the existing catalog")
	reason := flags.String("reason", "", "why these digests are revoked")
	validFor := flags.Duration("valid-for", 7*24*time.Hour,
		"how long the new catalog stays fresh; consumers deny once it expires")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return exitUsage
	}

	now := time.Now().UTC()
	snapshot := catalog.Snapshot{Sequence: 1, IssuedAt: now, ValidUntil: now.Add(*validFor)}

	// Extend the existing catalog when there is one, so the sequence advances and nothing
	// previously revoked is quietly dropped.
	if existing, err := attest.LoadEnvelope(*catalogPath); err == nil {
		trusted, err := attest.LoadTrustedKeys(*trustedPath)
		if err != nil {
			return fail(err)
		}
		previous, _, err := catalog.Verify(existing, trusted, nil, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: refusing to extend an unverifiable catalog: %v\n", err)
			return exitUsage
		}
		snapshot.Sequence = previous.Sequence + 1
		snapshot.Revoked = previous.Revoked
	} else if !os.IsNotExist(err) {
		return fail(err)
	}

	added := 0
	for _, digest := range flags.Args() {
		if _, present := snapshot.IsRevoked(digest); present {
			fmt.Fprintf(os.Stderr, "skillctl: %s is already revoked\n", digest)
			continue
		}
		snapshot.Revoked = append(snapshot.Revoked, catalog.Entry{
			Digest: digest, Reason: *reason, RevokedAt: now,
		})
		added++
	}

	key, err := attest.LoadPrivateKey(*keyPath)
	if err != nil {
		return fail(err)
	}
	envelope, err := catalog.Sign(snapshot, key)
	if err != nil {
		return fail(err)
	}
	if err := envelope.Save(*catalogPath); err != nil {
		return fail(err)
	}

	fmt.Printf("catalog     %s\n", *catalogPath)
	fmt.Printf("sequence    %d\n", snapshot.Sequence)
	fmt.Printf("revoked     %d total (%d added)\n", len(snapshot.Revoked), added)
	fmt.Printf("valid until %s\n", snapshot.ValidUntil.Format(time.RFC3339))
	return exitClean
}

func runCatalogShow(args []string) int {
	flags := flag.NewFlagSet("catalog show", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl catalog show [flags]\n\n"+
			"Verifies a catalog and prints it. Never prints an unverified one.\n\n"+
			"Exit codes: %d verified, %d not verified, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	catalogPath := flags.String("catalog", "catalog.json", "catalog to read")
	trustedPath := flags.String("trusted-keys", "trusted-keys.json", "pinned key set")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	trusted, err := attest.LoadTrustedKeys(*trustedPath)
	if err != nil {
		return fail(err)
	}
	envelope, err := attest.LoadEnvelope(*catalogPath)
	if err != nil {
		return fail(err)
	}

	state, err := catalog.LoadState(catalog.DefaultStatePath(*catalogPath))
	if err != nil {
		return fail(err)
	}

	snapshot, keyID, err := catalog.Verify(envelope, trusted, state, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: not verified: %v\n", err)
		return exitFindings
	}

	fmt.Printf("sequence    %d\n", snapshot.Sequence)
	fmt.Printf("issued      %s\n", snapshot.IssuedAt.Format(time.RFC3339))
	fmt.Printf("valid until %s\n", snapshot.ValidUntil.Format(time.RFC3339))
	fmt.Printf("signed by   %s\n\n", attest.Fingerprint(keyID))
	if len(snapshot.Revoked) == 0 {
		fmt.Println("nothing revoked")
		return exitClean
	}
	for _, entry := range snapshot.Revoked {
		fmt.Printf("  %s  %s\n", entry.Digest, entry.Reason)
	}
	return exitClean
}

func runSync(args []string) int {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl sync [flags] [path]\n\n"+
			"Reconciles installed skills against the signed revocation catalog. Reports by\n"+
			"default; --prune removes revoked skills from disk.\n\n"+
			"Exit codes: %d clean, %d revoked skills present, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	catalogPath := flags.String("catalog", "catalog.json", "signed revocation catalog")
	trustedPath := flags.String("trusted-keys", "trusted-keys.json", "pinned key set")
	prune := flags.Bool("prune", false, "delete revoked skills instead of only reporting them")
	maxDepth := flags.Int("max-depth", lint.DefaultMaxDepth, "maximum directory depth to scan")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	root, err := resolveRoot(flags)
	if err != nil {
		return fail(err)
	}

	trusted, err := attest.LoadTrustedKeys(*trustedPath)
	if err != nil {
		return fail(err)
	}
	envelope, err := attest.LoadEnvelope(*catalogPath)
	if err != nil {
		return fail(err)
	}

	statePath := catalog.DefaultStatePath(*catalogPath)
	state, err := catalog.LoadState(statePath)
	if err != nil {
		return fail(err)
	}

	now := time.Now().UTC()
	snapshot, _, err := catalog.Verify(envelope, trusted, state, now)
	if err != nil {
		// An unusable catalog is not "nothing is revoked". Reporting a clean tree here
		// would be the same defect as treating an unreadable lock as an absent one.
		fmt.Fprintf(os.Stderr, "skillctl: cannot use the catalog, so nothing was checked: %v\n", err)
		return exitUsage
	}
	if err := state.Save(statePath, snapshot.Sequence, now); err != nil {
		return fail(err)
	}

	directories, _ := lint.Discover(root, lint.Options{MaxDepth: *maxDepth})
	type hit struct {
		name      string
		directory string
		entry     catalog.Entry
	}
	var hits []hit
	checked := 0

	for _, directory := range directories {
		result, err := archive.Build(directory, archive.Limits{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: cannot digest %s: %v\n", directory, err)
			return exitUsage
		}
		checked++
		entry, revoked := snapshot.IsRevoked(result.Digest)
		if !revoked {
			continue
		}
		name, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
		if name == "" {
			name = filepath.Base(directory)
		}
		hits = append(hits, hit{name: name, directory: directory, entry: entry})
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].directory < hits[j].directory })

	fmt.Printf("skillctl sync  %s\n", root)
	fmt.Printf("catalog sequence %d, valid until %s\n\n",
		snapshot.Sequence, snapshot.ValidUntil.Format(time.RFC3339))

	for _, item := range hits {
		fmt.Printf("  revoked    %s\n", item.name)
		fmt.Printf("             %s\n", relativeOr(item.directory, root))
		fmt.Printf("             %s\n", item.entry.Digest)
		if item.entry.Reason != "" {
			fmt.Printf("             %s\n", item.entry.Reason)
		}
		if *prune {
			if err := os.RemoveAll(item.directory); err != nil {
				fmt.Fprintf(os.Stderr, "skillctl: cannot remove %s: %v\n", item.directory, err)
				return exitUsage
			}
			fmt.Printf("             removed\n")
		}
		fmt.Println()
	}

	fmt.Printf("%d checked · %d revoked\n", checked, len(hits))
	if len(hits) == 0 {
		fmt.Println("no installed skill appears in the revocation catalog.")
		return exitClean
	}
	if !*prune {
		fmt.Println("re-run with --prune to remove them.")
	}
	return exitFindings
}

func relativeOr(path, root string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return relative
}
