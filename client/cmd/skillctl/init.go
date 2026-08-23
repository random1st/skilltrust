package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/random1st/skilltrust/client/internal/attest"
)

func runInit(args []string) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl init [flags]\n\n"+
			"Prepares %s: a signing key and a pinned key set. Run once.\n\nFlags:\n", Home())
		flags.PrintDefaults()
	}

	label := flags.String("as", "", "identity recorded for your approvals (default your git email)")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	identity := *label
	if identity == "" {
		identity = gitIdentity()
	}
	if identity == "" {
		identity = "local"
	}

	if _, err := os.Stat(defaultSigningKey()); err == nil {
		fmt.Printf("already initialised\n\n")
		return printHome()
	}
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return fail(err)
	}

	public, private, err := attest.GenerateKey()
	if err != nil {
		return fail(err)
	}
	if err := attest.WritePrivateKey(defaultSigningKey(), private); err != nil {
		return fail(err)
	}
	if err := attest.WritePublicKey(defaultPublicKey(), public); err != nil {
		return fail(err)
	}
	// Pin, never replace. A machine that already follows marketplaces has their publisher
	// keys here, and writing a fresh file over them would silently unsubscribe it from
	// every one — which surfaces not as an error but as "no signature from a trusted key"
	// on the next check, reported as though the catalogs themselves had gone bad.
	if err := attest.PinKey(defaultTrustedKeys(), identity, public); err != nil {
		return fail(err)
	}

	fmt.Printf("initialised %s\n", Home())
	fmt.Printf("identity    %s\n", identity)
	fmt.Printf("key id      %s\n\n", attest.KeyID(public))
	fmt.Printf("Your key signs approvals and never leaves this machine. Share %s\n",
		filepath.Base(defaultPublicKey()))
	fmt.Printf("with anyone who needs to verify what you approved.\n\n")
	fmt.Printf("Next: skillctl status\n")
	return exitClean
}

func printHome() int {
	public, err := attest.LoadPublicKey(defaultPublicKey())
	if err != nil {
		return fail(err)
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return fail(err)
	}
	fmt.Printf("home        %s\n", Home())
	fmt.Printf("key id      %s\n", attest.KeyID(public))
	fmt.Printf("pinned keys %d\n", trusted.Len())
	return exitClean
}

// ensureSigningKey returns this machine's key, creating one on first use.
//
// It never replaces an existing key: overwriting the key that signed every approval and every
// report this machine has filed would invalidate all of them at once, and silently, since
// each of those signatures would simply stop matching.
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

	if identity == "" {
		identity = "local"
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
	if err := attest.PinKey(defaultTrustedKeys(), identity, public); err != nil {
		return nil, nil, false, err
	}
	return private, public, true, nil
}
