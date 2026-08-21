package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/client/internal/archive"
	"github.com/random1st/skilltrust/client/internal/attest"
	"github.com/random1st/skilltrust/client/internal/receipt"
	"github.com/random1st/skilltrust/client/internal/skillmd"
)

func runBundle(args []string) int {
	flags := flag.NewFlagSet("bundle", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), "Usage: skillctl bundle [flags] <skill-directory>\n\n"+
			"Writes the canonical archive of a skill directory. The file's digest is the\n"+
			"skill's identity, so a recipient can re-derive it without trusting the sender.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	out := flags.String("out", "", "bundle path (default <skill-directory>.tar)")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}

	directory, note, err := resolvePath(flags.Arg(0))
	if err != nil {
		return fail(err)
	}
	if note != "" {
		fmt.Fprintf(os.Stderr, "skillctl: %s\n", note)
	}

	built, err := archive.Build(directory, archive.Limits{})
	if err != nil {
		return fail(err)
	}

	path := *out
	if path == "" {
		path = filepath.Clean(directory) + ".tar"
	}
	if err := os.WriteFile(path, built.Payload, 0o644); err != nil {
		return fail(err)
	}

	fmt.Printf("bundle      %s\n", path)
	fmt.Printf("digest      %s\n", built.Digest)
	fmt.Printf("files       %d\n", len(built.Files))
	return exitClean
}

func runInstall(args []string) int {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl install [flags] <bundle>\n\n"+
			"Verifies a bundle and installs it into a skills directory, writing a receipt\n"+
			"recording the source and the approval it was installed under.\n\n"+
			"Exit codes: %d installed, %d verification failed, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	into := flags.String("into", ".agents/skills", "skills directory to install into")
	attestation := flags.String("attestation", "", "attestation over the bundle digest")
	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(), "pinned key set")
	unverified := flags.Bool("unverified", false,
		"install without an attestation; the receipt records that it was unapproved")
	force := flags.Bool("force", false, "replace an already installed skill of the same name")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}
	bundlePath := flags.Arg(0)
	attestationPath := *attestation
	if attestationPath == "" {
		attestationPath = findAttestation(bundlePath)
	}
	if attestationPath == "" && !*unverified {
		fmt.Fprintf(os.Stderr, "skillctl: no attestation found beside %s. Pass "+
			"--attestation, or --unverified to install without one; defaulting to "+
			"unverified would make the safe path the quiet one\n", bundlePath)
		return exitUsage
	}
	if *attestation == "" && attestationPath != "" {
		fmt.Fprintf(os.Stderr, "skillctl: using %s\n", attestationPath)
	}
	payload, err := os.ReadFile(bundlePath)
	if err != nil {
		return fail(err)
	}

	var approval *receipt.Approval
	expected := archive.DigestOf(payload)

	if attestationPath != "" {
		trusted, err := attest.LoadTrustedKeys(*trustedPath)
		if err != nil {
			return fail(err)
		}
		envelope, err := attest.LoadEnvelope(attestationPath)
		if err != nil {
			return fail(err)
		}
		statement, keyID, err := attest.Verify(envelope, trusted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: not installed: %v\n", err)
			return exitFindings
		}
		if statement.Subject.Digest != expected {
			fmt.Fprintf(os.Stderr,
				"skillctl: not installed: the attestation approves %s but the bundle is %s\n",
				statement.Subject.Digest, expected)
			return exitFindings
		}
		approval = &receipt.Approval{
			By: statement.ApprovedBy, At: statement.ApprovedAt, KeyID: keyID,
			Notes: statement.Notes,
		}
	}

	skillsRoot, err := filepath.Abs(*into)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(skillsRoot, 0o755); err != nil {
		return fail(err)
	}

	// Extract beside the destination rather than into it: nothing lands under a name a
	// client will read until the whole tree has been extracted and re-packaged to the
	// digest that was verified.
	staging, err := os.MkdirTemp(skillsRoot, ".skilltrust-staging-*")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(staging)

	unpacked := filepath.Join(staging, "payload")
	if _, err := archive.ExtractVerified(payload, unpacked, expected, archive.Limits{}); err != nil {
		return fail(err)
	}

	name, _ := skillmd.Parse(filepath.Join(unpacked, skillmd.FileName)).Name()
	if name == "" {
		fmt.Fprintln(os.Stderr, "skillctl: the bundle has no usable name in SKILL.md")
		return exitUsage
	}

	target := filepath.Join(skillsRoot, name)
	if _, err := os.Stat(target); err == nil {
		if !*force {
			fmt.Fprintf(os.Stderr, "skillctl: %s is already installed; pass --force to "+
				"replace it\n", name)
			return exitUsage
		}
		retired := staging + ".replaced"
		if err := os.Rename(target, retired); err != nil {
			return fail(err)
		}
		defer os.RemoveAll(retired)
	}

	if err := os.Rename(unpacked, target); err != nil {
		return fail(err)
	}

	record := &receipt.Receipt{
		Name: name, Digest: expected, Source: bundlePath,
		InstalledAt: time.Now(), Approval: approval,
	}
	if err := record.Save(receipt.Path(skillsRoot, name)); err != nil {
		return fail(err)
	}

	fmt.Printf("installed   %s\n", name)
	fmt.Printf("digest      %s\n", expected)
	fmt.Printf("into        %s\n", target)
	if approval != nil {
		fmt.Printf("approved by %s at %s\n", approval.By, approval.At.Format(time.RFC3339))
		fmt.Printf("key         %s\n", attest.Fingerprint(approval.KeyID))
	} else {
		fmt.Printf("approval    none — installed unverified\n")
	}
	fmt.Printf("receipt     %s\n", receipt.Path(skillsRoot, name))
	return exitClean
}

func runReceipts(args []string) int {
	flags := flag.NewFlagSet("receipts", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), "Usage: skillctl receipts [flags] [skills-directory]\n\n"+
			"Lists what was installed, from where, and on whose approval.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	root, err := resolveRoot(flags)
	if err != nil {
		return fail(err)
	}

	records, err := receipt.LoadAll(root)
	if err != nil {
		return fail(err)
	}
	if len(records) == 0 {
		fmt.Printf("no receipts under %s; nothing here was installed by skillctl\n", root)
		return exitClean
	}

	unapproved := 0
	for _, record := range records {
		fmt.Printf("  %-28s %s\n", record.Name, shortDigest(record.Digest))
		fmt.Printf("  %-28s from %s\n", "", record.Source)
		if record.Approval == nil {
			unapproved++
			fmt.Printf("  %-28s unapproved\n", "")
			continue
		}
		fmt.Printf("  %-28s approved by %s at %s\n", "",
			record.Approval.By, record.Approval.At.Format(time.RFC3339))
	}

	fmt.Printf("\n%d installed · %d unapproved\n", len(records), unapproved)
	return exitClean
}

// findAttestation looks beside the bundle for the approval that belongs to it.
//
// Requiring the path to be typed out every time is the kind of friction that gets solved
// with --unverified, and an unverified install is exactly what the flag exists to make
// deliberate rather than convenient.
func findAttestation(bundlePath string) string {
	base := strings.TrimSuffix(bundlePath, filepath.Ext(bundlePath))
	for _, candidate := range []string{
		bundlePath + ".att.json",
		base + ".att.json",
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}
