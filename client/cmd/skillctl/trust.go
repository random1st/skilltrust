package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/random1st/skilltrust/attest"
)

// runTrust manages the pinned keys directly, which is what an administrator collecting a
// fleet's machine keys actually does. Before this command existed the only ways in were
// `subscribe` — which pins catalog keys as a side effect — and editing the JSON by hand,
// and hand-edited trust roots are how typos become trust decisions.
func runTrust(args []string) int {
	flags := flag.NewFlagSet("trust", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl trust [flags] [file.pub]\n\n"+
			"Pins a public key, or shows what is pinned. With a file, the key is added under\n"+
			"--label (default: the file's name). With no arguments, lists the pinned set.\n\n"+
			"An administrator collecting machine keys for `skillctl fleet` pins each\n"+
			"machine's signer.pub this way:  skillctl trust laptop-roman.pub\n\n"+
			"Exit codes: %d done, %d error.\n\nFlags:\n", exitClean, exitUsage)
		flags.PrintDefaults()
	}

	keysPath := flags.String("trusted-keys", defaultTrustedKeys(), "the pinned-key file to change")
	label := flags.String("label", "", "name this key is pinned under (default the file's name)")
	remove := flags.String("remove", "", "unpin this label instead of adding anything")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}

	if *remove != "" {
		if flags.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "skillctl: --remove takes no file; it unpins by label")
			return exitUsage
		}
		if err := attest.UnpinKey(*keysPath, *remove); err != nil {
			return fail(err)
		}
		fmt.Printf("unpinned    %s\n", *remove)
		return exitClean
	}

	if flags.NArg() == 0 {
		return listTrusted(*keysPath)
	}
	if flags.NArg() > 1 {
		flags.Usage()
		return exitUsage
	}

	path := flags.Arg(0)
	public, err := attest.LoadPublicKey(path)
	if err != nil {
		return fail(err)
	}
	name := *label
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if err := attest.PinKey(*keysPath, name, public); err != nil {
		return fail(err)
	}
	fmt.Printf("pinned      %s\n", name)
	fmt.Printf("fingerprint %s\n", attest.Fingerprint(attest.KeyID(public)))
	fmt.Printf("in          %s\n", *keysPath)
	return exitClean
}

func listTrusted(keysPath string) int {
	keys, err := attest.PinnedKeys(keysPath)
	if err != nil {
		return fail(err)
	}
	if len(keys) == 0 {
		fmt.Printf("nothing pinned in %s\n", keysPath)
		return exitClean
	}

	labels := make([]string, 0, len(keys))
	for label := range keys {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	for _, label := range labels {
		fmt.Printf("  %-32s %s\n", label, attest.Fingerprint(attest.KeyID(keys[label])))
	}
	fmt.Printf("%d key%s pinned in %s\n", len(labels), plural(len(labels), "", "s"), keysPath)
	return exitClean
}
