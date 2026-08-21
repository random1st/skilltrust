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
	"github.com/random1st/skilltrust/client/internal/lockfile"
	"github.com/random1st/skilltrust/client/internal/receipt"
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

	keyPath := flags.String("key", defaultSigningKey(), "signing key")
	catalogPath := flags.String("catalog", defaultCatalog(), "catalog to extend, created if absent")
	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(), "pinned keys, to read the existing catalog")
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

	catalogPath := flags.String("catalog", defaultCatalog(), "catalog to read")
	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(), "pinned key set")

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

// syncStatus is what sync learned about one installed skill. The four questions are
// deliberately separate: a skill can be revoked, or unmanaged, or drifted from what was
// recorded, and collapsing them into "ok/not ok" throws away the part that says what to do.
type syncStatus struct {
	name      string
	directory string
	digest    string
	revoked   *catalog.Entry
	record    *receipt.Receipt
	drifted   bool
	// expected and pinnedBy are the digest drift was measured against and where it came
	// from. sync resolves them by the same rule as verify — the lock first, the receipt
	// where the lock is silent — because two commands answering "did this change" from
	// different baselines is how one of them ends up trusted and the other ignored.
	expected string
	pinnedBy lockfile.PinnedBy
}

func runSync(args []string) int {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl sync [flags] [path]\n\n"+
			"Reconciles installed skills against the revocation catalog and what was recorded\n"+
			"about them: what is revoked, what nobody installed through skillctl, and what has\n"+
			"drifted from the digest its lock entry or receipt recorded.\n\n"+
			"Exit codes: %d clean, %d something needs attention, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	catalogPath := flags.String("catalog", "",
		"signed revocation catalog (default the one in your skilltrust home, if present)")
	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(), "pinned key set")
	prune := flags.Bool("prune", false, "delete revoked skills instead of only reporting them")
	managed := flags.Bool("managed", false,
		"require every skill to have an approved receipt; use this on a fleet you control")
	maxDepth := flags.Int("max-depth", lint.DefaultMaxDepth, "maximum directory depth to scan")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	root, err := resolveRoot(flags)
	if err != nil {
		return fail(err)
	}

	now := time.Now().UTC()
	var snapshot *catalog.Snapshot

	catalogFile := *catalogPath
	if catalogFile == "" {
		if info, err := os.Stat(defaultCatalog()); err == nil && info.Mode().IsRegular() {
			catalogFile = defaultCatalog()
		}
	}

	if catalogFile == "" {
		// Saying nothing here would let "no catalog configured" read as "nothing is
		// revoked", which is the failure this tool refuses everywhere else.
		fmt.Fprintln(os.Stderr, "skillctl: no revocation catalog, so revocation was not checked")
	} else {
		trusted, err := attest.LoadTrustedKeys(*trustedPath)
		if err != nil {
			return fail(err)
		}
		envelope, err := attest.LoadEnvelope(catalogFile)
		if err != nil {
			return fail(err)
		}
		statePath := catalog.DefaultStatePath(catalogFile)
		state, err := catalog.LoadState(statePath)
		if err != nil {
			return fail(err)
		}
		snapshot, _, err = catalog.Verify(envelope, trusted, state, now)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"skillctl: cannot use the catalog, so nothing was checked: %v\n", err)
			return exitUsage
		}
		if err := state.Save(statePath, snapshot.Sequence, now); err != nil {
			return fail(err)
		}
	}

	receipts, err := receipt.LoadAll(root)
	if err != nil {
		return fail(err)
	}
	byName := make(map[string]*receipt.Receipt, len(receipts))
	for _, record := range receipts {
		byName[record.Name] = record
	}

	// A missing lock is ordinary — not every tree is pinned. An unreadable one is not, and
	// must not pass for the same thing: that is the silent off switch verify already refuses.
	byPath := map[string]lockfile.Entry{}
	lockPath := filepath.Join(root, lockfile.FileName)
	if lock, err := lockfile.Load(lockPath); err == nil {
		for _, entry := range lock.Skills {
			byPath[entry.Path] = entry
		}
	} else if !os.IsNotExist(err) {
		return fail(err)
	}

	directories, _ := lint.Discover(root, lint.Options{MaxDepth: *maxDepth})
	statuses := make([]syncStatus, 0, len(directories))

	for _, directory := range directories {
		result, err := archive.Build(directory, archive.Limits{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: cannot digest %s: %v\n", directory, err)
			return exitUsage
		}
		name, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
		if name == "" {
			name = filepath.Base(directory)
		}

		status := syncStatus{name: name, directory: directory, digest: result.Digest}
		if snapshot != nil {
			if entry, revoked := snapshot.IsRevoked(result.Digest); revoked {
				status.revoked = &entry
			}
		}
		if record, ok := byName[name]; ok {
			status.record = record
		}
		switch entry, isPinned := byPath[filepath.ToSlash(relativeOr(directory, root))]; {
		case isPinned:
			status.expected, status.pinnedBy = entry.Digest, lockfile.PinnedByLock
		case status.record != nil:
			status.expected, status.pinnedBy = status.record.Digest, lockfile.PinnedByReceipt
		}
		status.drifted = status.expected != "" && status.expected != result.Digest
		statuses = append(statuses, status)
	}

	sort.Slice(statuses, func(i, j int) bool { return statuses[i].name < statuses[j].name })
	return reportSync(statuses, snapshot, root, *prune, *managed)
}

func reportSync(
	statuses []syncStatus, snapshot *catalog.Snapshot, root string, prune, managed bool,
) int {
	fmt.Printf("skillctl sync  %s\n", root)
	if snapshot != nil {
		fmt.Printf("catalog sequence %d, valid until %s\n",
			snapshot.Sequence, snapshot.ValidUntil.Format(time.RFC3339))
	}
	fmt.Println()

	revoked, unmanaged, unapproved, drifted := 0, 0, 0, 0

	for _, status := range statuses {
		switch {
		case status.revoked != nil:
			revoked++
			fmt.Printf("  revoked    %s\n", status.name)
			fmt.Printf("             %s\n", relativeOr(status.directory, root))
			if status.revoked.Reason != "" {
				fmt.Printf("             %s\n", status.revoked.Reason)
			}
			if prune {
				if err := os.RemoveAll(status.directory); err != nil {
					fmt.Fprintf(os.Stderr, "skillctl: cannot remove %s: %v\n", status.directory, err)
					return exitUsage
				}
				_ = receipt.Remove(root, status.name)
				fmt.Printf("             removed\n")
			}
			fmt.Println()

		case status.drifted:
			drifted++
			fmt.Printf("  drifted    %s\n", status.name)
			fmt.Printf("             %s %s\n", expectedLabel(status.pinnedBy), status.expected)
			fmt.Printf("             on disk   %s\n", status.digest)
			fmt.Println()

		case status.record == nil:
			unmanaged++

		case status.record.Approval == nil:
			unapproved++
		}
	}

	if managed {
		for _, status := range statuses {
			if status.revoked != nil || status.drifted {
				continue
			}
			if status.record == nil {
				fmt.Printf("  unmanaged  %s\n             %s\n\n",
					status.name, relativeOr(status.directory, root))
			} else if status.record.Approval == nil {
				fmt.Printf("  unapproved %s\n             installed from %s\n\n",
					status.name, status.record.Source)
			}
		}
	}

	fmt.Printf("%d checked · %d revoked · %d drifted · %d unmanaged · %d unapproved\n",
		len(statuses), revoked, drifted, unmanaged, unapproved)

	problems := revoked + drifted
	if managed {
		problems += unmanaged + unapproved
	}
	if problems == 0 {
		if !managed && (unmanaged > 0 || unapproved > 0) {
			fmt.Printf("%d skills were not installed by skillctl; --managed makes that a failure.\n",
				unmanaged+unapproved)
		}
		return exitClean
	}
	if revoked > 0 && !prune {
		fmt.Println("re-run with --prune to remove the revoked ones.")
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
