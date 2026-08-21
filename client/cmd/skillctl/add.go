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
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/receipt"
	"github.com/random1st/skilltrust/client/internal/skillmd"
	"github.com/random1st/skilltrust/client/internal/source"
)

// runAdd installs skills from a git repository, signing each one as it lands.
//
// Signing at install time is the whole point. An approval produced by scanning a tree
// somebody else populated describes bytes that whatever populated them can replace at any
// moment — which is not hypothetical: a marketplace `git pull` changed four skills on this
// machine between one command and the next, and the signature covering them was already
// stale by the time anyone looked.
//
// Skills are copied, not symlinked. A symlink leaves the installed bytes owned by the
// repository, so an upstream fetch silently rewrites what was approved and drift stops
// meaning anything. With a copy, installing is the only way the bytes move, so a difference
// afterwards is a real finding rather than a stale link.
func runAdd(args []string) int {
	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl add [flags] <git-url>\n\n"+
			"Fetches a repository of skills, signs each one, and installs it. Re-running\n"+
			"updates the checkout and reports what moved before anything is replaced.\n\n"+
			"Exit codes: %d installed, %d something needs your decision, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	name := flags.String("name", "", "short name for this source (default the repository name)")
	ref := flags.String("ref", "", "branch or tag to install from (default the repository's HEAD)")
	into := flags.String("into", "", "skills directory to install into (default ~/.agents/skills)")
	only := flags.String("only", "", "install just this one skill from the repository")
	label := flags.String("as", "", "identity recorded in the approvals (default your git email)")
	approve := flags.Bool("approve", false, "re-approve skills whose upstream bytes changed")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}
	repository := flags.Arg(0)

	identity := *label
	if identity == "" {
		identity = gitIdentity()
	}
	if identity == "" {
		identity = "local"
	}

	sourceName := *name
	if sourceName == "" {
		sourceName = source.NameFor(repository)
	}
	if sourceName == "" {
		fmt.Fprintf(os.Stderr, "skillctl: cannot derive a name from %q; pass --name\n", repository)
		return exitUsage
	}

	target, err := installRoot(*into)
	if err != nil {
		return fail(err)
	}

	key, _, _, err := ensureSigningKey(identity)
	if err != nil {
		return fail(err)
	}

	fmt.Printf("fetching    %s\n", repository)
	fetched, err := source.Fetch(Home(), sourceName, repository, *ref)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("source      %s @ %s\n", fetched.Name, shortCommit(fetched.Commit))

	candidates, _ := lint.Discover(source.SkillRoot(Home(), sourceName), lint.Options{})
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "skillctl: no SKILL.md found in %s\n", repository)
		return exitUsage
	}

	plan, err := planInstall(candidates, target, fetched, *only)
	if err != nil {
		return fail(err)
	}
	if len(plan) == 0 {
		fmt.Fprintf(os.Stderr, "skillctl: %q is not in this repository\n", *only)
		return exitUsage
	}

	return applyInstall(plan, target, fetched, key, identity, *approve)
}

// change is what installing one skill would do to what is already on disk.
type change int

const (
	changeNew change = iota
	changeUnchanged
	changeUpstream // upstream moved since this skill was approved
	changeLocal    // the installed copy no longer matches its own receipt
)

type plannedSkill struct {
	name      string
	directory string
	digest    string
	change    change
	installed string // the digest the receipt approved
	onDisk    string // what the installed copy actually is now
}

func planInstall(candidates []string, target string, fetched source.Source, only string) ([]plannedSkill, error) {
	existing, err := receipt.LoadAll(target)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*receipt.Receipt, len(existing))
	for _, record := range existing {
		byName[record.Name] = record
	}

	var plan []plannedSkill
	for _, directory := range candidates {
		declared, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
		if declared == "" {
			continue
		}
		if only != "" && declared != only {
			continue
		}
		built, err := archive.Build(directory, archive.Limits{})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", declared, err)
		}

		item := plannedSkill{name: declared, directory: directory, digest: built.Digest, change: changeNew}
		if record, known := byName[declared]; known {
			item.installed = record.Digest

			// What is on disk is asked first, and unconditionally. Comparing the receipt
			// against upstream alone answers "is there a new release" and says nothing about
			// the copy actually being loaded — so an edited installed skill read as
			// "unchanged" for as long as upstream stood still, which is most of the time and
			// exactly when tampering is worth hiding.
			item.onDisk = digestOfInstalled(target, declared)
			switch {
			case item.onDisk != record.Digest:
				item.change = changeLocal
			case record.Digest == built.Digest:
				item.change = changeUnchanged
			default:
				item.change = changeUpstream
			}
		}
		plan = append(plan, item)
	}
	sort.Slice(plan, func(i, j int) bool { return plan[i].name < plan[j].name })
	return plan, nil
}

// digestOfInstalled is what the installed copy is right now, which is what separates
// "upstream moved" from "somebody edited the copy here". An unreadable copy returns the empty
// string and so compares unequal to any receipt: a skill that cannot be digested is not one
// that matched.
func digestOfInstalled(target, name string) string {
	built, err := archive.Build(filepath.Join(target, name), archive.Limits{})
	if err != nil {
		return ""
	}
	return built.Digest
}

func applyInstall(
	plan []plannedSkill, target string, fetched source.Source,
	key ed25519.PrivateKey, identity string, approve bool,
) int {
	store := attestationStore()
	if err := os.MkdirAll(store, 0o700); err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fail(err)
	}

	installed, updated, held, unchanged := 0, 0, 0, 0
	fmt.Println()

	for _, item := range plan {
		switch item.change {
		case changeUnchanged:
			unchanged++
			continue

		case changeUpstream, changeLocal:
			// Never replace approved bytes without being told to. The difference between an
			// upstream release and someone editing the installed copy is exactly the
			// difference this tool exists to surface, and overwriting either one on sight
			// would destroy the evidence before it was read.
			if !approve {
				held++
				if item.change == changeUpstream {
					fmt.Printf("  changed    %s   upstream moved since you approved it\n", item.name)
					fmt.Printf("             approved %s\n", item.installed)
					fmt.Printf("             upstream %s\n\n", item.digest)
				} else {
					fmt.Printf("  changed    %s   the installed copy was edited here\n", item.name)
					fmt.Printf("             approved %s\n", item.installed)
					fmt.Printf("             on disk  %s\n\n", displayDigest(item.onDisk))
				}
				continue
			}
			updated++

		case changeNew:
			installed++
		}

		if err := installSkill(item, target, fetched, key, identity, store); err != nil {
			return fail(err)
		}
		fmt.Printf("  %-10s %s   %s\n",
			map[change]string{changeNew: "installed", changeUpstream: "updated",
				changeLocal: "restored"}[item.change],
			item.name, shortDigest(item.digest))
	}

	fmt.Printf("\n%d installed · %d updated · %d unchanged · %d awaiting your decision\n",
		installed, updated, unchanged, held)
	fmt.Printf("into %s, signed as %s\n", target, identity)

	if held > 0 {
		fmt.Printf("\nRe-run with --approve to accept the changes above, after you have read them:\n")
		fmt.Printf("  skillctl add %s --approve\n", fetched.Repository)
		return exitFindings
	}
	return exitClean
}

// installSkill copies one skill into place and signs the bytes that landed.
//
// The copy is staged and swapped rather than written over the destination, so a failure
// halfway through cannot leave a half-written skill under a name the client will read and
// follow.
func installSkill(
	item plannedSkill, target string, fetched source.Source,
	key ed25519.PrivateKey, identity, store string,
) error {
	built, err := archive.Build(item.directory, archive.Limits{})
	if err != nil {
		return err
	}
	staging, err := os.MkdirTemp(target, ".skilltrust-staging-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	unpacked := filepath.Join(staging, "payload")
	if _, err := archive.ExtractVerified(built.Payload, unpacked, built.Digest, archive.Limits{}); err != nil {
		return err
	}

	destination := filepath.Join(target, item.name)
	if _, err := os.Stat(destination); err == nil {
		retired := staging + ".replaced"
		if err := os.Rename(destination, retired); err != nil {
			return err
		}
		defer os.RemoveAll(retired)
	}
	if err := os.Rename(unpacked, destination); err != nil {
		return err
	}

	now := time.Now().UTC()
	envelope, _, err := attest.Sign(attest.Statement{
		Version:    attest.StatementVersion,
		Subject:    attest.Subject{Name: item.name, Digest: built.Digest},
		ApprovedBy: identity,
		ApprovedAt: now,
		Source:     &attest.Source{Repository: fetched.Repository, Commit: fetched.Commit},
		Notes:      "installed by skillctl from " + fetched.Name,
	}, key)
	if err != nil {
		return err
	}
	if err := envelope.Save(attest.StorePath(store, item.name)); err != nil {
		return err
	}

	record := &receipt.Receipt{
		Name: item.name, Digest: built.Digest, InstalledAt: now,
		Source: receipt.Origin{
			Repository: fetched.Repository, Commit: fetched.Commit,
			Path: relativeOr(item.directory, source.Path(Home(), fetched.Name)),
		},
		Approval: &receipt.Approval{
			By: identity, At: now, KeyID: attest.KeyID(key.Public().(ed25519.PublicKey)),
			Notes: "signed at install",
		},
	}
	return record.Save(receipt.Path(target, item.name))
}

// installRoot is where skills land. Unlike the read-only commands this does not spread
// across every conventional location: writing into several trees because several exist is
// how a tool installs things somewhere its user was not looking.
func installRoot(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agents", "skills"), nil
}

// displayDigest names the case where a skill could not be digested at all, rather than
// printing an empty field that reads as "no change".
func displayDigest(digest string) string {
	if digest == "" {
		return "could not be read"
	}
	return digest
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
