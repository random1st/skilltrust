package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/lint"
	"github.com/random1st/skilltrust/client/internal/lockfile"
	"github.com/random1st/skilltrust/client/internal/skillmd"
)

// runSetup takes a machine from nothing to a notarized, watched skills tree in one command.
//
// It exists because the pieces did not add up to a product. Getting here previously meant
// init, then finding every skills directory, then signing each skill, then writing a lock,
// then wiring two hooks by hand-editing JSON — five steps, four of which require knowing
// what the tool is for before you can use it. The complexity was real; putting it in the
// user's way was a choice, and the wrong one.
//
// Everything it does is reversible, and it says how at the end. A setup command that cannot
// be undone is one people are right to refuse to run.
func runSetup(args []string) int {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl setup [flags] [path]\n\n"+
			"Prepares this machine: a signing key, a signed approval for every skill you\n"+
			"have, and the two client hooks that check them. Safe to run again.\n\n"+
			"Exit codes: %d done, %d error.\n\nFlags:\n", exitClean, exitUsage)
		flags.PrintDefaults()
	}

	label := flags.String("as", "", "identity recorded in your approvals (default your git email)")
	noHooks := flags.Bool("no-hooks", false, "prepare the keys and approvals but do not touch client settings")
	strict := flags.Bool("strict", false, "make the pre-skill hook deny a changed skill instead of warning")
	settings := flags.String("settings", "", "client settings file (default the Claude user settings)")
	dryRun := flags.Bool("dry-run", false, "print what would happen and change nothing")
	uninstall := flags.Bool("uninstall", false, "remove the client hooks this wrote")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	if *uninstall {
		return runSetupUninstall(*settings)
	}

	identity := *label
	if identity == "" {
		identity = gitIdentity()
	}
	if identity == "" {
		identity = "local"
	}

	roots, err := resolveSkillRoots(flags.Arg(0))
	if err != nil {
		return fail(err)
	}

	if *dryRun {
		return describeSetup(roots, identity, *noHooks, *strict, *settings)
	}

	// 1. A key, if there is not one already. Never replaced: overwriting the key that signed
	//    every existing approval would invalidate all of them at once, silently.
	key, public, created, err := ensureSigningKey(identity)
	if err != nil {
		return fail(err)
	}
	if created {
		fmt.Printf("created     %s\n", Home())
		fmt.Printf("identity    %s\n", identity)
		fmt.Printf("key         %s\n\n", attest.Fingerprint(attest.KeyID(public)))
	} else {
		fmt.Printf("home        %s (key already present)\n\n", Home())
	}

	// 2. A signed approval per skill, and a lock per tree. Both, because they answer
	//    different questions: the signature is what survives someone editing the tree, the
	//    lock is what can still name which file inside a skill moved.
	store := attestationStore()
	if err := os.MkdirAll(store, 0o700); err != nil {
		return fail(err)
	}

	totalSigned, totalSkipped := 0, 0
	for _, root := range roots {
		signed, skipped, err := notarizeTree(root, store, key, identity)
		if err != nil {
			return fail(err)
		}
		totalSigned += signed
		totalSkipped += skipped

		lock, err := lockfile.Build(root, lint.Options{})
		if err != nil {
			return fail(err)
		}
		if err := lock.Save(filepath.Join(root, lockfile.FileName)); err != nil {
			return fail(err)
		}
		fmt.Printf("%s\n", root)
		fmt.Printf("  notarized  %d skill%s\n", signed, plural(signed, "", "s"))
		if skipped > 0 {
			fmt.Printf("  unchanged  %d already signed at the same digest\n", skipped)
		}
		fmt.Printf("  pinned     %s\n\n", filepath.Join(root, lockfile.FileName))
	}

	// 3. The hooks, last: nothing should be watching until there is something to watch.
	if !*noHooks {
		path, err := claudeSettings(*settings)
		if err != nil {
			return fail(err)
		}
		added, err := applyClaudeHooks(path, clientHooks(executablePath(), *strict))
		if err != nil {
			return fail(err)
		}
		if len(added) == 0 {
			fmt.Printf("hooks       already configured in %s\n\n", path)
		} else {
			for _, spec := range added {
				fmt.Printf("hook        %-13s %s\n", spec.Event, spec.Why)
			}
			fmt.Printf("into        %s\n", path)
			fmt.Printf("backup      %s.skillctl-backup\n\n", path)
		}
	}

	fmt.Printf("%d skill%s signed. `skillctl status` any time.\n",
		totalSigned+totalSkipped, plural(totalSigned+totalSkipped, " is", "s are"))
	fmt.Printf("Undo: skillctl setup --uninstall  (removes the hooks; your keys and\n")
	fmt.Printf("approvals stay in %s until you delete them).\n", Home())
	return exitClean
}

// notarizeTree signs every skill under root that is not already signed at its current
// digest, and reports how many it signed and how many were already current.
//
// Re-signing a skill whose digest has not moved would churn the approval timestamp for no
// gain, so it is skipped. A skill whose digest *has* moved is signed afresh: that is the
// deliberate re-approval, and it is the only way an edited skill becomes trusted again.
func notarizeTree(root, store string, key ed25519.PrivateKey, identity string) (int, int, error) {
	directories, _ := lint.Discover(root, lint.Options{})

	signed, skipped := 0, 0
	for _, directory := range directories {
		built, err := archive.Build(directory, archive.Limits{})
		if err != nil {
			return signed, skipped, fmt.Errorf("%s: %w", directory, err)
		}
		name, _ := skillmd.Parse(filepath.Join(directory, skillmd.FileName)).Name()
		if name == "" {
			// Without a name in SKILL.md there is nothing to key an approval to, and
			// guessing from the directory would sign a claim about a skill the client will
			// not recognise under that name.
			continue
		}

		path := attest.StorePath(store, name)
		if existing, err := attest.LoadEnvelope(path); err == nil {
			if statement, _, err := attest.Verify(existing, attest.NewTrustedKeys(key.Public().(ed25519.PublicKey))); err == nil &&
				statement.Subject.Digest == built.Digest {
				skipped++
				continue
			}
		}

		envelope, _, err := attest.Sign(attest.Statement{
			Version:    attest.StatementVersion,
			Subject:    attest.Subject{Name: name, Digest: built.Digest},
			ApprovedBy: identity,
			ApprovedAt: time.Now().UTC(),
			Notes:      "approved by skillctl setup",
		}, key)
		if err != nil {
			return signed, skipped, err
		}
		if err := envelope.Save(path); err != nil {
			return signed, skipped, err
		}
		signed++
	}
	return signed, skipped, nil
}

// ensureSigningKey returns the machine's signing key, creating one on first run.
func ensureSigningKey(identity string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	if key, err := attest.LoadPrivateKey(defaultSigningKey()); err == nil {
		public, err := attest.LoadPublicKey(defaultPublicKey())
		if err != nil {
			return nil, nil, false, err
		}
		return key, public, false, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, false, err
	}

	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return nil, nil, false, err
	}
	public, private, err := attest.GenerateKey()
	if err != nil {
		return nil, nil, false, err
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), private); err != nil {
		return nil, nil, false, err
	}
	if err := attest.WritePublicKey(defaultPublicKey(), public); err != nil {
		return nil, nil, false, err
	}
	if err := attest.SaveTrustedKeys(defaultTrustedKeys(),
		map[string]ed25519.PublicKey{identity: public}); err != nil {
		return nil, nil, false, err
	}
	return private, public, true, nil
}

func describeSetup(roots []string, identity string, noHooks, strict bool, settings string) int {
	fmt.Printf("skillctl setup would:\n\n")
	if _, err := os.Stat(defaultSigningKey()); os.IsNotExist(err) {
		fmt.Printf("  create a signing key in %s as %s\n", Home(), identity)
	} else {
		fmt.Printf("  use the existing signing key in %s\n", Home())
	}
	for _, root := range roots {
		directories, _ := lint.Discover(root, lint.Options{})
		fmt.Printf("  sign %d skill%s under %s, and pin them in %s\n",
			len(directories), plural(len(directories), "", "s"), root, lockfile.FileName)
	}
	if !noHooks {
		path, _ := claudeSettings(settings)
		for _, spec := range clientHooks(executablePath(), strict) {
			fmt.Printf("  add a %s hook to %s — %s\n", spec.Event, path, spec.Why)
		}
	}
	fmt.Printf("\nNothing was changed. Run without --dry-run to do it.\n")
	return exitClean
}

func runSetupUninstall(settings string) int {
	path, err := claudeSettings(settings)
	if err != nil {
		return fail(err)
	}
	removed, err := removeClaudeHooks(path, "skillctl")
	if err != nil {
		return fail(err)
	}
	fmt.Printf("removed     %d hook%s from %s\n", removed, plural(removed, "", "s"), path)
	fmt.Printf("backup      %s.skillctl-backup\n\n", path)
	// Deliberately not deleted: the keys and approvals are the part that is expensive to
	// recreate and cheap to keep, and a command that quietly destroys signing material is
	// one nobody should run twice.
	fmt.Printf("Your key and approvals are untouched in %s.\n", Home())
	fmt.Printf("Delete them yourself if you mean to: rm -rf %s\n", Home())
	return exitClean
}
