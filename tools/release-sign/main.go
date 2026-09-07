// release-sign signs a release's checksums file with the release key, so a binary can
// verify an update came from us rather than from whoever controls the download host.
//
// The envelope is DSSE over the checksums text, the same shape as every other signature
// in SkillTrust, and the public half is compiled into skillctl. A release whose
// checksums do not verify against that key is refused by `skillctl update` no matter
// what GitHub serves.
//
//	release-sign -generate <private-key-path>   # once; prints the public key to embed
//	release-sign -key <private-key-path> <checksums-file>   # writes <file>.dsse.json
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/release"
)

func main() {
	generate := flag.String("generate", "", "create a new release key at this path (0600) and print its public half")
	keyPath := flag.String("key", "", "path to the release private key")
	flag.Parse()

	switch {
	case *generate != "":
		if _, err := os.Stat(*generate); err == nil {
			fail("refusing to overwrite %s; a release key is rotated by embedding a new public half, not by regenerating in place", *generate)
		}
		public, private, err := attest.GenerateKey()
		if err != nil {
			fail("%v", err)
		}
		if err := attest.WritePrivateKey(*generate, private); err != nil {
			fail("%v", err)
		}
		pem, err := attest.EncodePublicKey(public)
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("release key written to %s\nfingerprint %s\n\n%s", *generate, attest.Fingerprint(attest.KeyID(public)), pem)
	case *keyPath != "" && flag.NArg() == 1:
		private, err := attest.LoadPrivateKey(*keyPath)
		if err != nil {
			fail("%v", err)
		}
		checksums, err := os.ReadFile(flag.Arg(0))
		if err != nil {
			fail("%v", err)
		}
		envelope, err := release.SignChecksums(checksums, private)
		if err != nil {
			fail("%v", err)
		}
		out := flag.Arg(0) + release.SignatureSuffix
		if err := os.WriteFile(out, envelope, 0o644); err != nil {
			fail("%v", err)
		}
		fmt.Printf("signed %s -> %s\n", flag.Arg(0), out)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "release-sign: "+format+"\n", args...)
	os.Exit(1)
}
