package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/archive"
	"github.com/random1st/skilltrust/internal/lint"
	"github.com/random1st/skilltrust/internal/skillmd"
)

const attestUsage = `Usage: skillctl attest <subcommand> [flags]

  keygen   create a signing key pair
  sign     sign a skill directory's canonical digest
  verify   check a signed attestation against pinned keys

`

func runAttest(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, attestUsage)
		return exitUsage
	}
	switch args[0] {
	case "keygen":
		return runAttestKeygen(args[1:])
	case "sign":
		return runAttestSign(args[1:])
	case "verify":
		return runAttestVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown attest subcommand %q\n\n%s", args[0], attestUsage)
		return exitUsage
	}
}

func runAttestKeygen(args []string) int {
	flags := flag.NewFlagSet("attest keygen", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), "Usage: skillctl attest keygen [flags]\n\n"+
			"Creates an ed25519 signing key. The private half is written 0600 and never\n"+
			"leaves this machine; the public half and the key id are what you distribute.\n\n"+
			"Flags:\n")
		flags.PrintDefaults()
	}

	out := flags.String("out", filepath.Join(Home(), "signer"),
		"base path: writes <out>.key and <out>.pub")
	label := flags.String("label", "", "label recorded in the trusted-key file (default the key id)")
	trustOut := flags.String("trusted-keys", "",
		"also write a trusted-key file pinning this key, ready for `attest verify`")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	public, private, err := attest.GenerateKey()
	if err != nil {
		return fail(err)
	}

	privatePath, publicPath := *out+".key", *out+".pub"
	if _, err := os.Stat(privatePath); err == nil {
		// Overwriting a signing key silently would invalidate every attestation made
		// with it, with no way to tell that is what happened.
		fmt.Fprintf(os.Stderr, "skillctl: %s already exists; refusing to overwrite a "+
			"signing key\n", privatePath)
		return exitUsage
	}
	if err := attest.WritePrivateKey(privatePath, private); err != nil {
		return fail(err)
	}
	if err := attest.WritePublicKey(publicPath, public); err != nil {
		return fail(err)
	}

	keyID := attest.KeyID(public)
	if *trustOut != "" {
		name := *label
		if name == "" {
			name = keyID
		}
		if err := attest.SaveTrustedKeys(*trustOut,
			map[string]ed25519.PublicKey{name: public}); err != nil {
			return fail(err)
		}
	}

	fmt.Printf("key id      %s\n", keyID)
	fmt.Printf("private     %s  (0600, keep it here)\n", privatePath)
	fmt.Printf("public      %s\n", publicPath)
	if *trustOut != "" {
		fmt.Printf("trusted     %s\n", *trustOut)
	}
	return exitClean
}

func runAttestSign(args []string) int {
	flags := flag.NewFlagSet("attest sign", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), "Usage: skillctl attest sign [flags] <skill-directory>\n\n"+
			"Signs the canonical digest of a skill directory, recording who approved it\n"+
			"and when. The signature covers the exact statement bytes.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	keyPath := flags.String("key", defaultSigningKey(), "signing key")
	approvedBy := flags.String("as", "", "who approved these bytes (default your git email)")
	notes := flags.String("notes", "", "free-text note recorded in the statement")
	repository := flags.String("repository", "", "source repository, recorded for audit")
	commit := flags.String("commit", "", "source commit, recorded for audit")
	out := flags.String("out", "", "attestation path (default <skill-directory>.att.json)")
	// Without this the store had no way to be filled, which is how it ended up written,
	// documented and called by nothing.
	store := flags.Bool("store", false,
		"write into this machine's attestation store, where `attest verify` with no "+
			"argument looks and where deleting the skill cannot take it. On its own this "+
			"replaces the file beside the skill; pass --out as well to write both")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}
	identity := *approvedBy
	if identity == "" {
		identity = gitIdentity()
	}
	if identity == "" {
		fmt.Fprintln(os.Stderr, "skillctl: pass --as; no git email is configured, and an "+
			"approval nobody signed for cannot answer the question an audit asks")
		return exitUsage
	}

	directory, note, err := resolvePath(flags.Arg(0))
	if err != nil {
		return fail(err)
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}

	result, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		return fail(err)
	}
	name, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
	if name == "" {
		name = filepath.Base(directory)
	}

	key, err := attest.LoadPrivateKey(*keyPath)
	if err != nil {
		return fail(err)
	}

	statement := attest.Statement{
		Subject:    attest.Subject{Name: name, Digest: result.Digest},
		ApprovedBy: identity,
		ApprovedAt: time.Now(),
		Notes:      *notes,
	}
	if *repository != "" || *commit != "" {
		statement.Source = &attest.Source{Repository: *repository, Commit: *commit}
	}

	envelope, signed, err := attest.Sign(statement, key)
	if err != nil {
		return fail(err)
	}

	// Where the attestation goes, and the reason the two flags compose rather than stack.
	//
	// The first version always wrote the sibling and let --store add a second copy. That
	// forced a file into the skills tree on every machine that wanted the durable half —
	// seven of them, in a directory nobody had put an .att.json in — which is litter this
	// tool has no business leaving behind to record something it was asked to keep
	// elsewhere. --out still names a path explicitly, and asking for both is spelling both.
	path := *out
	if path == "" && !*store {
		path = attest.DefaultName(directory)
	}
	if path != "" {
		if err := envelope.Save(path); err != nil {
			return fail(err)
		}
	}

	fmt.Printf("signed      %s\n", signed.Subject.Name)
	fmt.Printf("digest      %s\n", signed.Subject.Digest)
	fmt.Printf("approved by %s at %s\n", signed.ApprovedBy,
		signed.ApprovedAt.Format(time.RFC3339))
	fmt.Printf("key         %s\n", attest.Fingerprint(envelope.Signatures[0].KeyID))
	if path != "" {
		fmt.Printf("attestation %s\n", path)
	}

	if *store {
		directory := homePath(attest.StoreDirectory)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fail(err)
		}
		kept := attest.StorePath(directory, signed.Subject.Name)
		if err := envelope.Save(kept); err != nil {
			return fail(err)
		}
		fmt.Printf("store       %s\n", kept)
	}
	return exitClean
}

func runAttestVerify(args []string) int {
	flags := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl attest verify [flags] [skill-directory]\n\n"+
			"Recomputes a directory's digest and checks a signed attestation over it\n"+
			"against pinned keys. Offline: no network, no service, no vendor.\n\n"+
			"With no directory, checks every skill on this machine against the approvals\n"+
			"in %s and any beside a skill. Skills nobody\n"+
			"approved are counted, not reported one by one: most skills on a laptop are\n"+
			"somebody's own.\n\n"+
			"Exit codes: %d verified, %d changed since approval, %d error.\n\nFlags:\n",
			homePath(attest.StoreDirectory), exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	attestation := flags.String("attestation", "", "attestation path (default <skill-directory>.att.json)")
	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(), "pinned key set")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 1 {
		flags.Usage()
		return exitUsage
	}

	trusted, err := attest.LoadTrustedKeys(*trustedPath)
	if err != nil {
		return fail(err)
	}

	// No directory named means every skill this machine has. That is the question people
	// actually have — "is anything here not what was approved?" — and asking it one
	// directory at a time is how it stops being asked.
	if flags.NArg() == 0 {
		if *attestation != "" {
			fmt.Fprintln(os.Stderr, "skillctl: --attestation names one file, so name the "+
				"skill directory it belongs to as well")
			return exitUsage
		}
		return verifyEverySkill(trusted)
	}

	directory, note, err := resolvePath(flags.Arg(0))
	if err != nil {
		return fail(err)
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}

	path := *attestation
	if path == "" {
		path = attest.DefaultName(directory)
	}
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		return fail(err)
	}

	statement, keyID, err := attest.Verify(envelope, trusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: not verified: %v\n", err)
		return exitFindings
	}

	// A valid signature over the wrong bytes is the failure this whole product exists to
	// catch, so the digest is recomputed here rather than taken from the statement.
	result, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		return fail(err)
	}
	if result.Digest != statement.Subject.Digest {
		fmt.Fprintf(os.Stderr, "skillctl: not verified: %v\n  approved %s\n  on disk  %s\n",
			attest.ErrDigestMismatch, statement.Subject.Digest, result.Digest)
		return exitFindings
	}

	fmt.Printf("verified    %s\n", statement.Subject.Name)
	fmt.Printf("digest      %s\n", statement.Subject.Digest)
	fmt.Printf("approved by %s at %s\n", statement.ApprovedBy,
		statement.ApprovedAt.Format(time.RFC3339))
	fmt.Printf("key         %s (%d pinned)\n", attest.Fingerprint(keyID), trusted.Len())
	if statement.Notes != "" {
		fmt.Printf("notes       %s\n", statement.Notes)
	}
	return exitClean
}

// verifyEverySkill checks every skill on this machine against the approvals it holds.
//
// This is the loose-skill half of the product, and until now it existed only as an API
// nobody called: attest.LoadStore was written, documented and wired to nothing. That matters
// more since the client list grew, because three of the four clients supported here install
// nothing from a marketplace — for Cursor and Antigravity, "are these the bytes somebody
// approved?" is a question the marketplace path cannot answer at all.
//
// An approval is looked for in the machine's store first and beside the skill second. The
// store is the durable half: an attestation living next to what it approves is deleted by
// whatever deletes that thing, which is exactly what a `git clean` or a reinstall does. The
// sibling is honoured anyway, because it is what `attest sign` writes by default and
// stranding those would make the two halves of one command disagree.
func verifyEverySkill(trusted *attest.TrustedKeys) int {
	roots, err := resolveSkillRoots("")
	if err != nil {
		return fail(err)
	}

	approvals, notes, err := attest.LoadStore(homePath(attest.StoreDirectory), trusted)
	if err != nil {
		return fail(err)
	}
	// First, and on stderr. An attestation that does not verify is the single most
	// interesting file in the store — corrupt or forged — and burying it under a list of
	// skills that were fine is how the strongest available signal gets read as noise.
	for _, note := range notes {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}

	// Grouped by name before anything is judged, because the store is keyed by name and a
	// machine can hold two different skills called the same thing — this one does, with an
	// adapty-cli in ~/.agents/skills and another in ~/.codex/skills carrying different
	// files. One approval cannot describe both. Reporting the loser as "changed" would
	// accuse it of drifting from an approval that was never about it, and re-signing to
	// clear the accusation just moves it to the other copy: a loop with no exit.
	type candidate struct {
		directory string
		digest    string
		err       error
	}
	byName := map[string][]candidate{}
	var order []string
	for _, root := range roots {
		directories, _ := lint.Discover(root, lint.Options{})
		for _, directory := range directories {
			name, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
			if name == "" {
				name = filepath.Base(directory)
			}
			// Recomputed from disk, never taken from the statement. A valid signature over
			// the wrong bytes is the whole failure this product exists to catch.
			built, err := archive.Build(directory, archive.Limits{})
			one := candidate{directory: directory, err: err}
			if err == nil {
				one.digest = built.Digest
			}
			if _, seen := byName[name]; !seen {
				order = append(order, name)
			}
			byName[name] = append(byName[name], one)
		}
	}
	sort.Strings(order)

	verified, changed, unapproved, ambiguous := 0, 0, 0, 0
	for _, name := range order {
		copies := byName[name]

		approval, held := approvals[name]
		if !held {
			for _, one := range copies {
				if envelope, err := attest.LoadEnvelope(attest.DefaultName(one.directory)); err == nil {
					if statement, keyID, err := attest.Verify(envelope, trusted); err == nil {
						approval = attest.Approval{
							Name: statement.Subject.Name, Digest: statement.Subject.Digest,
							ApprovedBy: statement.ApprovedBy, KeyID: keyID,
						}
						held = true
						break
					}
				}
			}
		}
		if !held {
			unapproved += len(copies)
			continue
		}

		matched := false
		for _, one := range copies {
			if one.err == nil && one.digest == approval.Digest {
				matched = true
				break
			}
		}

		for _, one := range copies {
			switch {
			case one.err != nil:
				fmt.Fprintf(os.Stderr, "skillctl: %s could not be read: %v\n", one.directory, one.err)
				changed++
			case one.digest == approval.Digest:
				verified++
			case matched:
				// Another directory holds the approved bytes, so this one is not a changed
				// copy of an approved skill — it is a second skill wearing the same name,
				// which is a thing to resolve rather than a thing to re-approve.
				fmt.Printf("  same name  %-28s %s\n", name, one.directory)
				// Not "rename one of them", which is what this said until it was pointed at
				// ~/.codex/skills/.system/skill-creator — a skill Codex ships, sitting
				// beside imagegen and openai-docs. Telling somebody to rename a file their
				// client installed is advice that is undone by the next update at best.
				// Which copy is theirs to move is not a question this tool can answer, so
				// it names the path and leaves the choice where it belongs.
				fmt.Printf("             another skill is approved under this name. If this "+
					"copy is yours, rename it; if your client shipped it, give it a name of "+
					"its own and approve that:\n             skillctl attest sign %s --store\n",
					one.directory)
				ambiguous++
			default:
				fmt.Printf("  changed    %-28s approved by %s\n", name, approval.ApprovedBy)
				fmt.Printf("             approved %s\n             on disk  %s\n",
					approval.Digest, one.digest)
				if len(copies) > 1 {
					fmt.Printf("             %s\n", one.directory)
				}
				changed++
			}
		}
	}

	// Unapproved is a count and not a list, and not a failure. Most skills on a laptop are
	// somebody's own, and a check that treats every personal skill as a finding is one that
	// gets run once. Saying nothing at all would be the other error: silence about a skill
	// nobody signed reads as a skill that was approved.
	fmt.Printf("%d verified · %d changed · %d with no approval on this machine",
		verified, changed, unapproved)
	if ambiguous > 0 {
		fmt.Printf(" · %d sharing a name with an approved skill", ambiguous)
	}
	fmt.Println()
	if changed > 0 {
		return exitFindings
	}
	return exitClean
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
	return exitUsage
}
