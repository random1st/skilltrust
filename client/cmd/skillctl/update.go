package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/release"
)

// Self-update for a verifier is the highest-value target on the machine, so the rule is
// simple: the binary accepts only what the release key signed, never what the download
// host served. The checksums come out of a DSSE envelope verified against the key
// compiled in below; the archive must match those checksums; the new binary must run
// and name the version it claims; only then is the running one replaced, atomically.
//
// Two deliberate limits. A Homebrew install is Homebrew's to update — replacing a file
// under its prefix leaves brew believing it manages a version it does not — so on those
// installs this defers to `brew upgrade`. And the session-start hook never rewrites the
// binary by default: it says an update exists, once a day, and applies it only where
// `skillctl update --auto on` was chosen. A verifier that silently rewrites itself when
// a session starts is exactly what a security review would flag first.

var (
	// releaseBase is where releases are published; tests point it at a local server.
	releaseBase = "https://github.com/random1st/skilltrust/releases"
	// releaseKeys are the keys a release must be signed by; tests substitute their own.
	releaseKeys = func() *attest.TrustedKeys {
		key, err := attest.ParsePublicKey([]byte(releasePublicKeyPEM))
		if err != nil {
			panic("the embedded release key does not parse: " + err.Error())
		}
		return attest.NewTrustedKeys(key)
	}
	// updateNow lets tests freeze the clock for the once-a-day check.
	updateNow = func() time.Time { return time.Now().UTC() }
	// updateCheckInterval is how often the session hook may look for a release.
	updateCheckInterval = 24 * time.Hour
	// verifyInstalled runs a freshly extracted binary and checks it names the expected
	// version. Tests replace it: a fake archive holds no runnable binary.
	verifyInstalled = func(binary, version string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, "--version").CombinedOutput()
		if err != nil {
			return fmt.Errorf("the downloaded binary did not run: %v: %s", err, strings.TrimSpace(string(out)))
		}
		if !strings.Contains(string(out), version) {
			return fmt.Errorf("the downloaded binary reports %q, not version %s", strings.TrimSpace(string(out)), version)
		}
		return nil
	}
	// currentExecutable is the binary being replaced; tests point it at a file of
	// their own rather than at the test binary.
	currentExecutable = func() (string, error) {
		self, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(self)
	}
	// brewUpgrade is how a Homebrew-managed install is updated; tests replace it.
	brewUpgrade = func() error {
		command := exec.Command("brew", "upgrade", "--cask", "random1st/tap/skillctl")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		return command.Run()
	}
)

// The binaries every release archive ships. Only those already present beside the
// running one are replaced: an install that never had `axela` does not gain it.
var releaseBinaries = []string{"skillctl", "axela", "skilltrust-mcp"}

const updateUsage = `Usage: skillctl update [flags]

Updates skillctl (and axela and skilltrust-mcp beside it) to the latest release.

A release is accepted only if its checksums verify against the release key compiled
into this binary, the downloaded archive matches those checksums, and the new binary
runs and names the version it claims. Homebrew installs are updated through brew.

  skillctl update             download, verify and install the latest release
  skillctl update --check     say whether a newer release exists, change nothing
  skillctl update --auto on   let the session-start hook apply verified updates itself
  skillctl update --auto off  back to a once-a-day notice (the default)

Exit codes: 0 up to date or updated, 1 a newer release exists (--check), 3 error.

Flags:
`

func runUpdate(args []string) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(flags.Output(), updateUsage); flags.PrintDefaults() }
	check := flags.Bool("check", false, "report only; download and install nothing")
	auto := flags.String("auto", "", "on or off: whether the session-start hook applies updates itself")
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return exitUsage
	}

	if *auto != "" {
		if *auto != "on" && *auto != "off" {
			fmt.Fprintf(os.Stderr, "skillctl: -auto takes on or off\n")
			return exitUsage
		}
		state, _ := loadUpdateState()
		state.Auto = *auto == "on"
		if err := saveUpdateState(state); err != nil {
			return fail(err)
		}
		if state.Auto {
			fmt.Println("auto-update  on: the session-start hook installs verified releases itself")
		} else {
			fmt.Println("auto-update  off: the session-start hook only says when a release exists")
		}
		return exitClean
	}

	current, ok := release.ParseVersion(resolveVersion())
	if !ok {
		fmt.Printf("version     %s\nupdate      not for development builds; install a release from %s\n", resolveVersion(), releaseBase)
		return exitClean
	}
	latest, err := latestRelease(context.Background(), 30*time.Second)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("installed   %s\nlatest      %s\n", current, latest)
	if !latest.Newer(current) {
		fmt.Println("status      up to date")
		return exitClean
	}
	if *check {
		fmt.Printf("status      %s is available; run %s update\n", latest, commandName())
		return exitFindings
	}
	if err := installRelease(context.Background(), latest, os.Stdout); err != nil {
		return fail(err)
	}
	return exitClean
}

// latestRelease asks the release host which tag "latest" points at. GitHub answers the
// /releases/latest URL with a redirect to /releases/tag/vX.Y.Z; reading the redirect
// needs no API, no token and no rate limit, and nothing here trusts what it says — the
// signature check below does.
func latestRelease(ctx context.Context, timeout time.Duration) (release.Version, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseBase+"/latest", nil)
	if err != nil {
		return release.Version{}, err
	}
	response, err := connectHTTPClient(timeout).Do(request)
	if err != nil {
		return release.Version{}, fmt.Errorf("the release host could not be reached: %w", err)
	}
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if response.StatusCode/100 != 3 || location == "" {
		return release.Version{}, fmt.Errorf("the release host did not name a latest release (%s)", response.Status)
	}
	tag := path.Base(location)
	latest, ok := release.ParseVersion(tag)
	if !ok {
		return release.Version{}, fmt.Errorf("the latest release is not a version: %q", tag)
	}
	return latest, nil
}

// installRelease is the whole path from a version to a replaced binary. Every step that
// can fail fails before anything on disk is touched, and the replacement itself is a
// rename, so there is no moment with half a binary in place.
func installRelease(ctx context.Context, version release.Version, out io.Writer) error {
	self, err := currentExecutable()
	if err != nil {
		return err
	}
	if managedByHomebrew(self) {
		fmt.Fprintf(out, "install     Homebrew (%s)\n", self)
		fmt.Fprintf(out, "updating    brew upgrade --cask random1st/tap/skillctl\n")
		return brewUpgrade()
	}

	sums, err := fetchVerifiedChecksums(ctx, version)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "signature   release key %s verified\n", releaseKeyFingerprint())

	name, err := release.ArchiveName(version.String(), runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	expected, listed := sums[name]
	if !listed {
		return fmt.Errorf("the signed checksums do not list %s", name)
	}
	archive, err := fetch(ctx, releaseBase+"/download/v"+version.String()+"/"+name, 256<<20)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(archive)
	if hex.EncodeToString(digest[:]) != expected {
		return fmt.Errorf("%s does not match its signed checksum; refusing it", name)
	}
	fmt.Fprintf(out, "archive     %s sha256 %s… verified\n", name, expected[:12])

	files, err := extractBinaries(name, archive)
	if err != nil {
		return err
	}
	directory := filepath.Dir(self)
	staged := map[string]string{}
	defer func() {
		for _, p := range staged {
			os.Remove(p)
		}
	}()
	for _, binary := range releaseBinaries {
		fileName := binary + exeSuffix()
		body, shipped := files[fileName]
		if !shipped {
			continue
		}
		target := filepath.Join(directory, fileName)
		if fileName != filepath.Base(self) {
			if _, err := os.Stat(target); err != nil {
				continue // not installed here; do not introduce it
			}
		}
		stage := filepath.Join(directory, "."+fileName+".update")
		if err := os.WriteFile(stage, body, 0o755); err != nil {
			return fmt.Errorf("cannot stage %s beside the current binary: %w", fileName, err)
		}
		staged[target] = stage
	}
	newSelf, ok := staged[self]
	if !ok {
		return fmt.Errorf("the archive does not contain %s", filepath.Base(self))
	}
	if err := verifyInstalled(newSelf, version.String()); err != nil {
		return err
	}
	for target, stage := range staged {
		if err := replaceBinary(stage, target); err != nil {
			return fmt.Errorf("cannot replace %s: %w", target, err)
		}
		delete(staged, target)
		fmt.Fprintf(out, "installed   %s\n", target)
	}
	state, _ := loadUpdateState()
	state.Latest, state.CheckedAt = version.String(), updateNow()
	_ = saveUpdateState(state)
	fmt.Fprintf(out, "status      updated to %s\n", version)
	return nil
}

func fetchVerifiedChecksums(ctx context.Context, version release.Version) (map[string]string, error) {
	url := releaseBase + "/download/v" + version.String() + "/" + release.ChecksumsName(version.String()) + release.SignatureSuffix
	envelope, err := fetch(ctx, url, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("the release signature could not be fetched: %w", err)
	}
	return release.VerifyChecksums(envelope, releaseKeys())
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Downloads follow redirects (GitHub serves assets from a CDN); the latest lookup
	// above deliberately does not, which is why it does not share this client.
	response, err := (&http.Client{Timeout: 5 * time.Minute}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", url, limit)
	}
	return body, nil
}

// extractBinaries reads the release binaries out of the archive by base name. Paths in
// the archive are ignored on purpose: a member named ../../bin/skillctl must not be
// able to choose where it lands.
func extractBinaries(name string, archive []byte) (map[string][]byte, error) {
	wanted := map[string]bool{}
	for _, binary := range releaseBinaries {
		wanted[binary+exeSuffix()] = true
	}
	files := map[string][]byte{}
	keep := func(memberName string, body io.Reader) error {
		base := path.Base(strings.ReplaceAll(memberName, "\\", "/"))
		if !wanted[base] {
			return nil
		}
		content, err := io.ReadAll(io.LimitReader(body, 256<<20))
		if err != nil {
			return err
		}
		files[base] = content
		return nil
	}
	switch {
	case strings.HasSuffix(name, ".zip"):
		reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, fmt.Errorf("the archive is not a zip: %w", err)
		}
		for _, member := range reader.File {
			if member.FileInfo().IsDir() {
				continue
			}
			body, err := member.Open()
			if err != nil {
				return nil, err
			}
			err = keep(member.Name, body)
			body.Close()
			if err != nil {
				return nil, err
			}
		}
	case strings.HasSuffix(name, ".tar.gz"):
		unzipped, err := gzip.NewReader(bytes.NewReader(archive))
		if err != nil {
			return nil, fmt.Errorf("the archive is not gzip: %w", err)
		}
		reader := tar.NewReader(unzipped)
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if header.Typeflag != tar.TypeReg {
				continue
			}
			if err := keep(header.Name, reader); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unknown archive format: %s", name)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("the archive holds none of the release binaries")
	}
	return files, nil
}

// replaceBinary puts the staged file in the target's place. On POSIX a rename over a
// running executable is atomic and the old inode lives on until the process exits. On
// Windows the running file cannot be overwritten but can be renamed, so it is moved
// aside first; the .old is removed on a later run.
func replaceBinary(stage, target string) error {
	if runtime.GOOS == "windows" {
		old := target + ".old"
		os.Remove(old)
		if err := os.Rename(target, old); err != nil {
			return err
		}
		if err := os.Rename(stage, target); err != nil {
			_ = os.Rename(old, target)
			return err
		}
		return nil
	}
	return os.Rename(stage, target)
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func managedByHomebrew(self string) bool {
	normalized := filepath.ToSlash(self)
	for _, marker := range []string{"/Cellar/", "/Caskroom/", "/opt/homebrew/", "/usr/local/Homebrew/", "/home/linuxbrew/"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func releaseKeyFingerprint() string {
	key, err := attest.ParsePublicKey([]byte(releasePublicKeyPEM))
	if err != nil {
		return "unknown"
	}
	return attest.Fingerprint(attest.KeyID(key))
}

// updateState is the once-a-day memory and the one preference.
type updateState struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest,omitempty"`
	Auto      bool      `json:"auto,omitempty"`
}

func updateStatePath() string { return homePath("update.json") }

func loadUpdateState() (updateState, error) {
	var state updateState
	raw, err := os.ReadFile(updateStatePath())
	if err != nil {
		return state, err
	}
	return state, json.Unmarshal(raw, &state)
}

func saveUpdateState(state updateState) error {
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(updateStatePath(), raw, 0o600)
}

// writeUpdateNotice is the session-start hook's part: one line when a release exists,
// at most one lookup a day, two seconds at most, silence on any failure — a hook that
// delays or alarms every session because a release host is slow would be removed by
// the first person it annoyed. With --auto on it installs the verified release instead.
func writeUpdateNotice(out io.Writer) {
	if os.Getenv("SKILLTRUST_NO_UPDATE_CHECK") != "" {
		return
	}
	current, ok := release.ParseVersion(resolveVersion())
	if !ok {
		return
	}
	state, _ := loadUpdateState()
	now := updateNow()
	if now.Sub(state.CheckedAt) >= updateCheckInterval {
		latest, err := latestRelease(context.Background(), 2*time.Second)
		if err != nil {
			return
		}
		state.Latest, state.CheckedAt = latest.String(), now
		_ = saveUpdateState(state)
	}
	latest, ok := release.ParseVersion(state.Latest)
	if !ok || !latest.Newer(current) {
		return
	}
	if state.Auto {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := installRelease(ctx, latest, io.Discard); err != nil {
			fmt.Fprintf(out, "skillctl: %s is available but could not be installed automatically: %v\n", latest, err)
			return
		}
		fmt.Fprintf(out, "skillctl: updated to %s; the new version runs from the next session\n", latest)
		return
	}
	fmt.Fprintf(out, "skillctl: %s is available (you have %s); run %s update\n", latest, current, commandName())
}
