package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
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
		storeDir := homePath(attest.StoreDirectory)
		if err := os.MkdirAll(storeDir, 0o700); err != nil {
			return fail(err)
		}
		// Keyed by name and place, so approving this skill cannot silently destroy the
		// approval of a different skill that happens to share its name.
		kept := attest.StorePath(storeDir, signed.Subject.Name, directory)
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
	_, _, code := verifyEverySkillReporting(trusted, false)
	return code
}

// verifyEverySkillReporting is verifyEverySkill plus the drift it found, for the caller that
// files it. Split rather than given a flag: the reporting decision belongs to the session
// hook, and `attest verify` run by hand must stay the read-only thing its annotation claims.
// quiet keeps the session hook to the news. A hook that prints "107 verified" before every
// session is one people stop reading, and this one has to be read on the day a skill changed.
// What survives quiet is a skill that drifted and an attestation that will not verify; what
// does not is the tally and the advice about names, which are answers to a question somebody
// asked rather than something that just happened.
// A local observation supplies the inventory UI. It is not part of a signed check.
type skillObservation struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Verdict string `json:"verdict"`
	Error   string `json:"error,omitempty"`
}

type LooseSkillCheck struct {
	Scope        string             `json:"scope"`
	Coverage     string             `json:"coverage"`
	Complete     bool               `json:"complete"`
	CheckedAt    time.Time          `json:"checked_at"`
	Found        int                `json:"found"`
	Verified     int                `json:"verified"`
	Checked      int                `json:"checked"`
	Changed      int                `json:"changed,omitempty"`
	Unapproved   int                `json:"unapproved,omitempty"`
	Errors       int                `json:"errors,omitempty"`
	FirstIssue   string             `json:"-"`
	Observations []skillObservation `json:"-"`
}

func verifyEverySkillReporting(trusted *attest.TrustedKeys, quiet bool) (LooseSkillCheck, []skillDrift, int) {
	roots, err := resolveSkillRoots("")
	if err != nil {
		return LooseSkillCheck{Scope: CheckScopeApprovedSkills, CheckedAt: time.Now().UTC()}, nil, fail(err)
	}
	return verifySkillRootsReporting(trusted, quiet, roots)
}

func verifySkillRootsReporting(trusted *attest.TrustedKeys, quiet bool, roots []string) (LooseSkillCheck, []skillDrift, int) {
	return inspectSkillRoots(trusted, quiet, roots, os.Stdout, os.Stderr)
}

// The same verification supplies terminal checks and doctor's structured result.
// Neither path creates approvals or changes the skills it reads.
func inspectSkillRoots(trusted *attest.TrustedKeys, quiet bool, roots []string, output, diagnostics io.Writer) (LooseSkillCheck, []skillDrift, int) {
	summary := LooseSkillCheck{
		Scope:        CheckScopeApprovedSkills,
		CheckedAt:    time.Now().UTC(),
		Observations: []skillObservation{},
	}
	var drift []skillDrift

	approvals, notes, storeErr := attest.LoadStore(homePath(attest.StoreDirectory), trusted)
	if storeErr != nil {
		summary.Errors++
		fmt.Fprintf(diagnostics, "skillctl: %v\n", storeErr)
		// Still inventory readable skills; the verdict remains incomplete and failed.
	}
	// First, and on stderr. An attestation that does not verify is the single most
	// interesting file in the store — corrupt or forged — and burying it under a list of
	// skills that were fine is how the strongest available signal gets read as noise.
	summary.Errors += len(notes)
	for _, note := range notes {
		fmt.Fprintf(diagnostics, "skillctl: %s\n", note)
	}

	// Grouped by name before anything is judged, because a machine can hold two different
	// skills called the same thing — this one does, with an adapty-cli in ~/.agents/skills
	// and another in ~/.codex/skills carrying different files. Approvals are matched to
	// copies by digest, so each copy can hold its own; the grouping is what lets an
	// unapproved copy of a shared name be reported as "same name, not approved" rather
	// than accused of drifting from an approval that was never about it.
	type candidate struct {
		directory string
		digest    string
		err       error
	}
	byName := map[string][]candidate{}
	var order []string
	seenDirectories := map[string]bool{}
	for _, root := range roots {
		directories, notes := lint.Discover(root, lint.Options{})
		summary.Errors += len(notes)
		for _, note := range notes {
			fmt.Fprintf(diagnostics, "skillctl: %s\n", note)
		}
		for _, directory := range directories {
			resolved, resolveErr := filepath.EvalSymlinks(directory)
			if resolveErr == nil {
				if seenDirectories[resolved] {
					continue
				}
				seenDirectories[resolved] = true
			}
			summary.Found++
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

	verified, unapproved, ambiguous := 0, 0, 0
	for _, name := range order {
		copies := byName[name]
		observe := func(one candidate, verdict string) {
			observation := skillObservation{Name: name, Path: one.directory, Verdict: verdict}
			if verdict == "error" {
				observation.Error = one.err.Error()
			}
			summary.Observations = append(summary.Observations, observation)
		}

		held := approvals[name]
		for _, one := range copies {
			path := attest.DefaultName(one.directory)
			envelope, err := attest.LoadEnvelope(path)
			if os.IsNotExist(err) {
				if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
					continue
				}
			}
			var statement *attest.Statement
			var keyID string
			if err == nil {
				statement, keyID, err = attest.Verify(envelope, trusted)
			}
			if errors.Is(err, attest.ErrUntrustedKey) {
				// A publisher whose key is not pinned has no trusted approval here.
				continue
			}
			if err != nil {
				summary.Errors++
				fmt.Fprintf(diagnostics, "skillctl: %s could not be verified: %v\n", path, err)
				continue
			}
			held = append(held, attest.Approval{
				Name: statement.Subject.Name, Digest: statement.Subject.Digest,
				ApprovedBy: statement.ApprovedBy, KeyID: keyID,
			})
		}
		// A copy is verified by whichever approval covers its bytes. The store keeps one
		// approval per copy, so two skills sharing a name can each hold their own.
		covering := func(digest string) *attest.Approval {
			for i := range held {
				if held[i].Digest == digest {
					return &held[i]
				}
			}
			return nil
		}
		matched := false
		for _, one := range copies {
			if one.err == nil && covering(one.digest) != nil {
				matched = true
				break
			}
		}

		reportChanged := func(one candidate, against attest.Approval) {
			observe(one, "changed")
			fmt.Fprintf(output, "  changed    %-28s approved by %s\n", name, against.ApprovedBy)
			fmt.Fprintf(output, "             approved %s\n             on disk  %s\n",
				against.Digest, one.digest)
			if len(copies) > 1 {
				fmt.Fprintf(output, "             %s\n", one.directory)
			}
			if summary.FirstIssue == "" {
				summary.FirstIssue = one.directory
			}
			drift = append(drift, skillDrift{
				Name: name, ApprovedBy: against.ApprovedBy,
				Approved: against.Digest, OnDisk: one.digest,
			})
			summary.Checked++
			summary.Changed++
		}

		for _, one := range copies {
			here := approvedAt(one.directory, name, trusted)
			if one.err != nil {
				observe(one, "error")
				fmt.Fprintf(diagnostics, "skillctl: %s could not be read: %v\n", one.directory, one.err)
				if summary.FirstIssue == "" {
					summary.FirstIssue = one.directory
				}
				if here != nil || !matched {
					summary.Checked++
				}
				summary.Errors++
				continue
			}
			if len(held) == 0 {
				observe(one, "unapproved")
				unapproved++
				continue
			}
			if covering(one.digest) != nil {
				observe(one, "verified")
				verified++
				summary.Checked++
				continue
			}
			if here != nil {
				// This directory itself was approved — the store file is keyed by where the
				// skill lives — and its bytes no longer match. Without that key this copy
				// hid in the "same name" bucket whenever its twin still matched, which let
				// a changed skill pass behind a namesake's approval.
				reportChanged(one, *here)
				continue
			}
			if matched {
				observe(one, "unapproved")
				// Another directory holds approved bytes under this name, and nothing says
				// this one was ever approved: a second skill wearing the same name, not a
				// changed copy of the first.
				if quiet {
					ambiguous++
					continue
				}
				fmt.Fprintf(output, "  same name  %-28s %s\n", name, one.directory)
				fmt.Fprintf(output, "             another skill is approved under this name, and this "+
					"copy is not. If you trust these bytes too, approve them — each copy "+
					"keeps its own approval:\n             skillctl attest sign %s --store\n",
					one.directory)
				ambiguous++
				continue
			}
			reportChanged(one, held[0])
		}
	}
	summary.Verified = verified
	summary.Unapproved = unapproved + ambiguous
	switch {
	case summary.Checked == 0 && summary.Errors == 0:
		summary.Coverage = "empty"
	case summary.Errors > 0:
		summary.Coverage = "partial"
	default:
		summary.Coverage = "full"
		summary.Complete = true
	}

	// The attestation-only output keeps unapproved as a count, not a list or a failure. Most skills on a laptop are
	// somebody's own, and a check that treats every personal skill as a finding is one that
	// gets run once. Saying nothing at all would be the other error: silence about a skill
	// nobody signed reads as a skill that was approved.
	if !quiet {
		fmt.Fprintf(output, "%d verified · %d changed · %d with no approval on this machine",
			verified, summary.Changed, summary.Unapproved)
		if ambiguous > 0 {
			fmt.Fprintf(output, " · %d sharing a name with an approved skill", ambiguous)
		}
		if summary.Errors > 0 {
			fmt.Fprintf(output, " · %d error%s", summary.Errors, plural(summary.Errors, "", "s"))
		}
		fmt.Fprintln(output)
	}
	if storeErr != nil {
		return summary, drift, exitUsage
	}
	if summary.Changed > 0 || summary.Errors > 0 {
		return summary, drift, exitFindings
	}
	return summary, drift, exitClean
}

// approvedAt returns the approval recorded for the skill at this directory, if any: the
// store file keyed by this path, or the attestation beside it. This is what tells a changed
// copy of an approved skill apart from a namesake nobody ever approved.
func approvedAt(directory, name string, trusted *attest.TrustedKeys) *attest.Approval {
	for _, path := range []string{
		attest.StorePath(homePath(attest.StoreDirectory), name, directory),
		attest.DefaultName(directory),
	} {
		envelope, err := attest.LoadEnvelope(path)
		if err != nil {
			continue
		}
		statement, keyID, err := attest.Verify(envelope, trusted)
		if err != nil || statement.Subject.Name != name {
			continue
		}
		return &attest.Approval{
			Name: statement.Subject.Name, Digest: statement.Subject.Digest,
			ApprovedBy: statement.ApprovedBy, KeyID: keyID,
		}
	}
	return nil
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
	return exitUsage
}
