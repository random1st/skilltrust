package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/archive"
	"github.com/random1st/skilltrust/internal/marketplace"
)

func runDiff(args []string) int {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s diff [flags] <plugin>\n\n"+
			"Review a saved local change against the installed skill, without changing either.\n"+
			"Client dependencies, session locks, git metadata and signatures are excluded.\n"+
			"The next command keeps the exact saved payload you reviewed.\n\nFlags:\n", commandName())
		flags.PrintDefaults()
	}
	market := flags.String("marketplace", "", "catalog publishing the plugin")
	home := flags.String("claude-home", "", "client directory containing plugins/cache (default ~/.claude)")
	quarantined := flags.String("quarantine", "", "exact saved copy (default: newest copy for this installation)")
	savedVersion := flags.String("saved-version", "", "installed version the saved copy belonged to (for review across an upgrade)")
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}
	if *savedVersion != "" && (filepath.Base(*savedVersion) != *savedVersion || *savedVersion == "." || *savedVersion == ".." || strings.ContainsAny(*savedVersion, `/\`)) {
		return fail(fmt.Errorf("saved version must be one directory name"))
	}
	resolvedHome, err := recoveryHome(*home)
	if err != nil {
		return fail(err)
	}
	results, _, code := reconcileAll(resolvedHome, false, true)
	if code == exitUsage {
		return code
	}
	found, err := match(results, *market, flags.Arg(0))
	if err != nil {
		return fail(err)
	}
	installed := marketplace.InstalledPath(resolvedHome, found.Marketplace, found.Plugin, found.Version)
	savedTarget := installed
	if *savedVersion != "" {
		savedTarget = marketplace.InstalledPath(resolvedHome, found.Marketplace, found.Plugin, *savedVersion)
	}
	selected := *quarantined
	if selected == "" {
		var ok bool
		selected, ok, err = marketplace.NewestQuarantine(quarantineRoot(), savedTarget, found.Plugin)
		if err != nil {
			return fail(err)
		}
		if !ok {
			fmt.Printf("No saved copy for %q in this installation.\n", found.Plugin)
			return exitFindings
		}
	}
	selected, saved, err := marketplace.QuarantinePayload(selected, savedTarget, found.Plugin)
	if err != nil {
		return fail(err)
	}
	current, err := marketplace.InstalledPayload(installed)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Installed: %q\nSaved:     %q\n", installed, selected)
	changed, err := writePayloadDiff(os.Stdout, current, saved)
	if err != nil {
		return fail(err)
	}
	if !changed {
		fmt.Println("No skill payload changes.")
		return exitClean
	}
	if *savedVersion != "" && *savedVersion != found.Version {
		fmt.Println("This saved change belongs to an older published version. Re-apply the needed changes to the current version, then adopt that edit.")
		return exitFindings
	}
	if found.Outcome != marketplace.OutcomeVerified || current.Digest != found.Signed {
		fmt.Println("The installed copy is not the published version. Keep its current changes before recovering another copy.")
		return exitFindings
	}
	if err := recoveryAllowed(found, saved.Digest); err != nil {
		fmt.Printf("Recovery unavailable: %s\n", strconv.Quote(err.Error()))
		return exitFindings
	}
	found.ClientHome = resolvedHome
	_, adopt := quarantineCommands(found, selected, saved.Digest, "describe your intentional change")
	fmt.Println("To keep this exact saved copy, replace the reason in this command:")
	printNextCommand(adopt)
	return exitFindings
}

func recoveryHome(home string) (string, error) {
	if home == "" {
		home = marketplace.DefaultClaudeHome()
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}

// quarantineCommands carries argv, not shell fragments. Render it through the same
// quoting and non-printable-name guard as doctor's next command.
func quarantineCommands(result marketplace.Result, quarantined, digest, because string) (diff, adopt []string) {
	if !filepath.IsAbs(result.ClientHome) || quarantined == "" {
		return nil, nil
	}
	home, err := recoveryHome(result.ClientHome)
	if err != nil {
		return nil, nil
	}
	selection := []string{result.Plugin, "--marketplace", result.Marketplace,
		"--claude-home", home, "--quarantine", quarantined}
	diff = append([]string{commandName(), "diff"}, selection...)
	if result.Version != "" {
		diff = append(diff, "--saved-version", result.Version)
	}
	if digest != "" {
		adopt = append([]string{commandName(), "adopt"}, selection...)
		adopt = append(adopt, "--quarantine-digest", digest, "--because", because)
	}
	return diff, adopt
}

// Reconciliation checked the installed digest. Check the saved digest against the same
// signed catalog before moving it, so recovery cannot put withdrawn bytes back first and
// only discover their revocation during the later adoption check.
func recoveryAllowed(found marketplace.Result, digest string) error {
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return err
	}
	trusted, err := attest.LoadTrustedKeys(defaultTrustedKeys())
	if err != nil {
		return err
	}
	var matched []*catalog.Snapshot
	for _, subscription := range subscriptions {
		snapshot, err := readSnapshotOnly(subscription, trusted, time.Now().UTC())
		if err == nil && snapshot.Name == found.Marketplace {
			matched = append(matched, snapshot)
		}
	}
	if len(matched) != 1 {
		return fmt.Errorf("the catalog for %q is no longer unambiguously verified; check it again before recovery", found.Marketplace)
	}
	snapshot := matched[0]
	entry, ok := snapshot.Publishes(found.Plugin)
	if !ok || entry.Version != found.Version || entry.Digest != found.Signed {
		return fmt.Errorf("the published skill changed since this check; run diff again")
	}
	for _, candidate := range []string{entry.Digest, digest} {
		if revoked, ok := snapshot.IsRevoked(candidate); ok {
			return fmt.Errorf("this skill payload is revoked (%s) and cannot be recovered", revoked.Reason)
		}
	}
	return nil
}

type diffFile struct {
	body []byte
	mode int64
}

func payloadFiles(payload *archive.Archive) (map[string]diffFile, error) {
	files := make(map[string]diffFile, len(payload.Files))
	reader := tar.NewReader(bytes.NewReader(payload.Payload))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		files[header.Name] = diffFile{body, header.Mode}
	}
}

func writePayloadDiff(out io.Writer, installed, saved *archive.Archive) (bool, error) {
	before, err := payloadFiles(installed)
	if err != nil {
		return false, err
	}
	after, err := payloadFiles(saved)
	if err != nil {
		return false, err
	}
	var names []string
	for name := range before {
		names = append(names, name)
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	changed := 0
	for _, name := range names {
		left, leftOK := before[name]
		right, rightOK := after[name]
		if leftOK == rightOK && left.mode == right.mode && bytes.Equal(left.body, right.body) {
			continue
		}
		changed++
		oldName, newName := "installed/"+name, "saved/"+name
		if !leftOK {
			oldName = "/dev/null"
		}
		if !rightOK {
			newName = "/dev/null"
		}
		fmt.Fprintf(out, "\n--- %s\n+++ %s\n", strconv.Quote(oldName), strconv.Quote(newName))
		if left.mode != right.mode {
			fmt.Fprintf(out, "mode %04o -> %04o\n", left.mode, right.mode)
		}
		if bytes.Equal(left.body, right.body) {
			continue
		}
		if !diffableText(left.body) || !diffableText(right.body) {
			fmt.Fprintf(out, "Binary contents differ (%d -> %d bytes).\n", len(left.body), len(right.body))
			fmt.Fprintf(out, "sha256:%x -> sha256:%x\n", sha256.Sum256(left.body), sha256.Sum256(right.body))
			continue
		}
		if len(left.body)+len(right.body) > 1<<20 {
			fmt.Fprintf(out, "Text contents differ (%d -> %d bytes); too large for an inline diff.\n", len(left.body), len(right.body))
			fmt.Fprintf(out, "sha256:%x -> sha256:%x\n", sha256.Sum256(left.body), sha256.Sum256(right.body))
			continue
		}
		writeTextDiff(out, left.body, right.body)
	}
	fmt.Fprintf(out, "\n%d changed payload file(s).\n", changed)
	return changed > 0, nil
}

func diffableText(body []byte) bool {
	return utf8.Valid(body) && !bytes.ContainsRune(body, 0)
}

// A single contextual hunk is linear in the file size. It need not find a shortest edit
// script to show every changed byte; large and binary files are explicitly summarized.
func writeTextDiff(out io.Writer, oldBody, newBody []byte) {
	lines := func(body []byte) []string {
		parts := strings.SplitAfter(string(body), "\n")
		if parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
		return parts
	}
	before, after := lines(oldBody), lines(newBody)
	prefix, suffix := 0, 0
	for prefix < len(before) && prefix < len(after) && before[prefix] == after[prefix] {
		prefix++
	}
	for suffix < len(before)-prefix && suffix < len(after)-prefix &&
		before[len(before)-1-suffix] == after[len(after)-1-suffix] {
		suffix++
	}
	start := max(0, prefix-3)
	oldEnd, newEnd := min(len(before), len(before)-suffix+3), min(len(after), len(after)-suffix+3)
	oldStart, newStart := start+1, start+1
	if oldEnd == start {
		oldStart = start
	}
	if newEnd == start {
		newStart = start
	}
	fmt.Fprintf(out, "@@ -%d,%d +%d,%d @@\n", oldStart, oldEnd-start, newStart, newEnd-start)
	write := func(prefix byte, line string) {
		content := strings.TrimSuffix(line, "\n")
		if strings.IndexFunc(content, func(r rune) bool { return !unicode.IsPrint(r) && r != '\t' }) >= 0 {
			content = strconv.Quote(content)
		}
		fmt.Fprintf(out, "%c%s\n", prefix, content)
		if !strings.HasSuffix(line, "\n") {
			fmt.Fprintln(out, "\\ No newline at end of file")
		}
	}
	for _, line := range before[start:prefix] {
		write(' ', line)
	}
	for _, line := range before[prefix : len(before)-suffix] {
		write('-', line)
	}
	for _, line := range after[prefix : len(after)-suffix] {
		write('+', line)
	}
	for _, line := range before[len(before)-suffix : oldEnd] {
		write(' ', line)
	}
}
