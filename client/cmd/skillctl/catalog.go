package main

import (
	"crypto/ed25519"
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
	"github.com/random1st/skilltrust/client/internal/source"
)

const catalogUsage = `Usage: skillctl catalog <subcommand> [flags]

  publish  build and sign the index of skills a repository publishes
  revoke   add digests to the signed revocation catalog
  show     print a catalog after verifying it

`

func runCatalog(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, catalogUsage)
		return exitUsage
	}
	switch args[0] {
	case "publish":
		return runCatalogPublish(args[1:])
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

// runCatalogPublish signs the index of what a catalog repository publishes.
//
// This is the organisation's side of the product. The index is what makes central management
// possible at all: it names, under one signature, exactly which skills are managed and which
// bytes each is supposed to have. A machine never decides that for itself, which is what
// keeps the tool away from everything the catalog does not claim.
func runCatalogPublish(args []string) int {
	flags := flag.NewFlagSet("catalog publish", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl catalog publish [flags] [repository]\n\n"+
			"Digests every skill under skills/ and signs the resulting index into %s.\n"+
			"Carries forward the revocations already in the catalog and advances the\n"+
			"sequence, so a consumer cannot be walked backwards onto an older answer.\n\n"+
			"Exit codes: %d published, %d error.\n\nFlags:\n",
			CatalogFileName, exitClean, exitUsage)
		flags.PrintDefaults()
	}

	name := flags.String("name", "", "catalog name recorded in the index (default the directory name)")
	keyPath := flags.String("key", defaultSigningKey(), "signing key")
	validFor := flags.Duration("valid-for", 7*24*time.Hour,
		"how long consumers may keep using this index before it must be refreshed")

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
	catalogName := *name
	if catalogName == "" {
		catalogName = filepath.Base(repository)
	}

	skillsDir := filepath.Join(repository, source.SkillsSubdirectory)
	directories, _ := lint.Discover(skillsDir, lint.Options{})
	if len(directories) == 0 {
		fmt.Fprintf(os.Stderr, "skillctl: no skills found under %s\n", skillsDir)
		return exitUsage
	}

	now := time.Now().UTC()
	snapshot := catalog.Snapshot{
		Version: catalog.SnapshotVersion, Name: catalogName, Sequence: 1,
		IssuedAt: now, ValidUntil: now.Add(*validFor),
	}

	indexPath := filepath.Join(repository, CatalogFileName)
	key, err := attest.LoadPrivateKey(*keyPath)
	if err != nil {
		return fail(err)
	}

	// Republishing must not drop revocations or reuse a sequence: either would let a
	// consumer that already saw a newer index quietly accept an older set of claims.
	if existing, err := attest.LoadEnvelope(indexPath); err == nil {
		previous, _, err := catalog.Verify(existing,
			attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)), nil, now)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"skillctl: refusing to replace an index this key cannot verify: %v\n", err)
			return exitUsage
		}
		snapshot.Sequence = previous.Sequence + 1
		snapshot.Revoked = previous.Revoked
	} else if !os.IsNotExist(err) {
		return fail(err)
	}

	for _, directory := range directories {
		built, err := archive.Build(directory, archive.Limits{})
		if err != nil {
			return fail(err)
		}
		declared, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
		if declared == "" {
			fmt.Fprintf(os.Stderr, "skillctl: %s declares no name and cannot be published\n",
				relativeOr(directory, repository))
			return exitUsage
		}
		snapshot.Skills = append(snapshot.Skills, catalog.Managed{
			Name:   declared,
			Digest: built.Digest,
			Path:   filepath.ToSlash(relativeOr(directory, repository)),
		})
	}
	sort.Slice(snapshot.Skills, func(i, j int) bool {
		return snapshot.Skills[i].Name < snapshot.Skills[j].Name
	})

	envelope, err := catalog.Sign(snapshot, key)
	if err != nil {
		return fail(err)
	}
	if err := envelope.Save(indexPath); err != nil {
		return fail(err)
	}

	fmt.Printf("catalog     %s\n", catalogName)
	fmt.Printf("index       %s\n", indexPath)
	fmt.Printf("sequence    %d\n", snapshot.Sequence)
	fmt.Printf("publishes   %d skill%s\n", len(snapshot.Skills),
		plural(len(snapshot.Skills), "", "s"))
	fmt.Printf("revoked     %d\n", len(snapshot.Revoked))
	fmt.Printf("valid until %s\n\n", snapshot.ValidUntil.Format(time.RFC3339))
	for _, managed := range snapshot.Skills {
		fmt.Printf("  %s  %s\n", shortDigest(managed.Digest), managed.Name)
	}
	fmt.Printf("\nCommit %s so consumers can fetch it.\n", CatalogFileName)
	return exitClean
}
