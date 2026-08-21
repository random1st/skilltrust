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
	"github.com/random1st/skilltrust/client/internal/skillmd"
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

	path := *out
	if path == "" {
		path = attest.DefaultName(directory)
	}
	if err := envelope.Save(path); err != nil {
		return fail(err)
	}

	fmt.Printf("signed      %s\n", signed.Subject.Name)
	fmt.Printf("digest      %s\n", signed.Subject.Digest)
	fmt.Printf("approved by %s at %s\n", signed.ApprovedBy,
		signed.ApprovedAt.Format(time.RFC3339))
	fmt.Printf("key         %s\n", attest.Fingerprint(envelope.Signatures[0].KeyID))
	fmt.Printf("attestation %s\n", path)
	return exitClean
}

func runAttestVerify(args []string) int {
	flags := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl attest verify [flags] <skill-directory>\n\n"+
			"Recomputes the directory's digest and checks a signed attestation over it\n"+
			"against pinned keys. Offline: no network, no service, no vendor.\n\n"+
			"Exit codes: %d verified, %d not verified, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	attestation := flags.String("attestation", "", "attestation path (default <skill-directory>.att.json)")
	trustedPath := flags.String("trusted-keys", defaultTrustedKeys(), "pinned key set")

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

	trusted, err := attest.LoadTrustedKeys(*trustedPath)
	if err != nil {
		return fail(err)
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

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
	return exitUsage
}
