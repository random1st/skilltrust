package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/release"
)

// fakeRelease is a release host in miniature: the latest redirect, a signed checksums
// envelope, and one archive for this platform. Everything the updater trusts is
// produced here with a key the test controls, so a test can also sign with the wrong
// one or corrupt the archive and watch the refusal.
type fakeRelease struct {
	server    *httptest.Server
	version   string
	archive   []byte
	name      string
	envelope  []byte
	downloads atomic.Int32
}

func newFakeRelease(t *testing.T, version string, signer ed25519.PrivateKey, contents map[string][]byte) *fakeRelease {
	t.Helper()
	name, err := release.ArchiveName(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRelease{version: version, name: name, archive: buildArchive(t, name, contents)}
	sum := sha256.Sum256(f.archive)
	checksums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), name)
	f.envelope, err = release.SignChecksums([]byte(checksums), signer)
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/latest":
			w.Header().Set("Location", "/tag/v"+f.version)
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/download/v"+f.version+"/"+release.ChecksumsName(f.version)+release.SignatureSuffix:
			w.Write(f.envelope)
		case r.URL.Path == "/download/v"+f.version+"/"+f.name:
			f.downloads.Add(1)
			w.Write(f.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func buildArchive(t *testing.T, name string, contents map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if strings.HasSuffix(name, ".zip") {
		writer := zip.NewWriter(&buffer)
		for member, body := range contents {
			entry, err := writer.Create(member)
			if err != nil {
				t.Fatal(err)
			}
			entry.Write(body)
		}
		writer.Close()
		return buffer.Bytes()
	}
	gz := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(gz)
	for member, body := range contents {
		writer.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		writer.Write(body)
	}
	writer.Close()
	gz.Close()
	return buffer.Bytes()
}

// updateFixture points every injectable at the test: a fake install directory with a
// "skillctl" and a "skilltrust-mcp" but no "axela", a release key, a frozen clock, and a
// verifyInstalled that records what it was asked to verify.
type updateFixture struct {
	directory string
	self      string
	public    ed25519.PublicKey
	private   ed25519.PrivateKey
	verified  []string
	brewCalls int
}

func newUpdateFixture(t *testing.T) *updateFixture {
	t.Helper()
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &updateFixture{directory: t.TempDir(), public: public, private: private}
	f.self = filepath.Join(f.directory, "skillctl"+exeSuffix())
	for _, name := range []string{"skillctl", "skilltrust-mcp"} {
		if err := os.WriteFile(filepath.Join(f.directory, name+exeSuffix()), []byte("old "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	previous := struct {
		base    string
		keys    func() *attest.TrustedKeys
		now     func() time.Time
		verify  func(string, string) error
		exe     func() (string, error)
		brew    func() error
		version string
	}{releaseBase, releaseKeys, updateNow, verifyInstalled, currentExecutable, brewUpgrade, version}
	t.Cleanup(func() {
		releaseBase, releaseKeys, updateNow, verifyInstalled, currentExecutable, brewUpgrade, version =
			previous.base, previous.keys, previous.now, previous.verify, previous.exe, previous.brew, previous.version
	})
	releaseKeys = func() *attest.TrustedKeys { return attest.NewTrustedKeys(public) }
	updateNow = func() time.Time { return time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC) }
	verifyInstalled = func(binary, wanted string) error { f.verified = append(f.verified, binary+"@"+wanted); return nil }
	currentExecutable = func() (string, error) { return f.self, nil }
	brewUpgrade = func() error { f.brewCalls++; return nil }
	version = "1.0.0"
	return f
}

func (f *updateFixture) serve(t *testing.T, r *fakeRelease) { releaseBase = r.server.URL }

func (f *updateFixture) read(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(f.directory, name+exeSuffix()))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestUpdateReplacesWhatIsInstalledAndNothingElse(t *testing.T) {
	f := newUpdateFixture(t)
	f.serve(t, newFakeRelease(t, "1.2.0", f.private, map[string][]byte{
		"skillctl" + exeSuffix():       []byte("new skillctl"),
		"skilltrust-mcp" + exeSuffix(): []byte("new mcp"),
		"axela" + exeSuffix():          []byte("new axela"),
		"LICENSE":                      []byte("license"),
	}))

	var out bytes.Buffer
	latest, _ := release.ParseVersion("1.2.0")
	if err := installRelease(context.Background(), latest, &out); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	if f.read(t, "skillctl") != "new skillctl" || f.read(t, "skilltrust-mcp") != "new mcp" {
		t.Fatal("the installed binaries were not replaced")
	}
	if _, err := os.Stat(filepath.Join(f.directory, "axela"+exeSuffix())); err == nil {
		t.Fatal("a binary that was never installed here was introduced")
	}
	if len(f.verified) != 1 || !strings.HasSuffix(f.verified[0], "@1.2.0") {
		t.Fatalf("the new binary was not verified before the swap: %v", f.verified)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(f.directory, ".*.update")); len(leftovers) != 0 {
		t.Fatalf("staging files left behind: %v", leftovers)
	}
	state, err := loadUpdateState()
	if err != nil || state.Latest != "1.2.0" {
		t.Fatalf("state after update = %+v, %v", state, err)
	}
	for _, line := range []string{"signature   release key", "verified", "installed   " + f.self, "status      updated to 1.2.0"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output omits %q:\n%s", line, out.String())
		}
	}
}

// The signature is checked before the archive is even requested: a release host that
// cannot produce a valid signature gets no chance to serve a binary.
func TestUpdateRefusesAReleaseSignedByAnotherKey(t *testing.T) {
	f := newUpdateFixture(t)
	_, stranger, _ := attest.GenerateKey()
	r := newFakeRelease(t, "1.2.0", stranger, map[string][]byte{"skillctl" + exeSuffix(): []byte("evil")})
	f.serve(t, r)

	latest, _ := release.ParseVersion("1.2.0")
	err := installRelease(context.Background(), latest, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "does not verify against the release key") {
		t.Fatalf("a stranger's release was accepted: %v", err)
	}
	if r.downloads.Load() != 0 {
		t.Fatal("the archive was downloaded before the signature was checked")
	}
	if f.read(t, "skillctl") != "old skillctl" {
		t.Fatal("the binary was touched")
	}
}

func TestUpdateRefusesAnArchiveThatDoesNotMatchItsChecksum(t *testing.T) {
	f := newUpdateFixture(t)
	r := newFakeRelease(t, "1.2.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("signed bytes")})
	// Swap the served archive after signing: the host lies, the signature does not.
	r.archive = buildArchive(t, r.name, map[string][]byte{"skillctl" + exeSuffix(): []byte("other bytes")})
	f.serve(t, r)

	latest, _ := release.ParseVersion("1.2.0")
	err := installRelease(context.Background(), latest, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "does not match its signed checksum") {
		t.Fatalf("a mismatched archive was accepted: %v", err)
	}
	if f.read(t, "skillctl") != "old skillctl" || len(f.verified) != 0 {
		t.Fatal("something ran or changed on a refused archive")
	}
}

func TestUpdateDoesNotSwapABinaryThatFailsToRun(t *testing.T) {
	f := newUpdateFixture(t)
	f.serve(t, newFakeRelease(t, "1.2.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("broken")}))
	verifyInstalled = func(string, string) error { return fmt.Errorf("segfault") }

	latest, _ := release.ParseVersion("1.2.0")
	if err := installRelease(context.Background(), latest, io.Discard); err == nil {
		t.Fatal("a binary that does not run was installed")
	}
	if f.read(t, "skillctl") != "old skillctl" {
		t.Fatal("the working binary was replaced by one that does not run")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(f.directory, ".*.update")); len(leftovers) != 0 {
		t.Fatalf("staging files left behind: %v", leftovers)
	}
}

// A member path is not allowed to choose where a file lands.
func TestExtractIgnoresWhereAnArchiveSaysAFileGoes(t *testing.T) {
	name, _ := release.ArchiveName("1.0.0", runtime.GOOS, runtime.GOARCH)
	files, err := extractBinaries(name, buildArchive(t, name, map[string][]byte{
		"../../../../bin/skillctl" + exeSuffix():  []byte("x"),
		"nested/dir/skilltrust-mcp" + exeSuffix(): []byte("y"),
		"README.md": []byte("ignored"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if string(files["skillctl"+exeSuffix()]) != "x" || string(files["skilltrust-mcp"+exeSuffix()]) != "y" || len(files) != 2 {
		t.Fatalf("extracted = %v", files)
	}
}

func TestHomebrewInstallsAreLeftToBrew(t *testing.T) {
	f := newUpdateFixture(t)
	r := newFakeRelease(t, "1.2.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("new")})
	f.serve(t, r)
	currentExecutable = func() (string, error) { return "/opt/homebrew/Caskroom/skillctl/1.0.0/skillctl", nil }

	latest, _ := release.ParseVersion("1.2.0")
	if err := installRelease(context.Background(), latest, io.Discard); err != nil {
		t.Fatal(err)
	}
	if f.brewCalls != 1 || r.downloads.Load() != 0 {
		t.Fatalf("brew calls = %d, downloads = %d", f.brewCalls, r.downloads.Load())
	}
}

// The hook looks at most once a day, says one line, and changes nothing unless auto
// was chosen. Silence on failure is part of the contract: a session must not stall or
// alarm because a release host is slow.
func TestSessionNoticeLooksOnceADayAndInstallsOnlyWhenAsked(t *testing.T) {
	f := newUpdateFixture(t)
	r := newFakeRelease(t, "1.2.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("new")})
	f.serve(t, r)
	var lookups atomic.Int32
	inner := r.server.Config.Handler
	r.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/latest" {
			lookups.Add(1)
		}
		inner.ServeHTTP(w, req)
	})

	var out bytes.Buffer
	writeUpdateNotice(&out)
	writeUpdateNotice(&out)
	if lookups.Load() != 1 {
		t.Fatalf("the hook asked the release host %d times in one day", lookups.Load())
	}
	if strings.Count(out.String(), "1.2.0 is available (you have 1.0.0); run skillctl update") != 2 {
		t.Fatalf("notice = %q", out.String())
	}
	if f.read(t, "skillctl") != "old skillctl" {
		t.Fatal("the hook replaced the binary without being asked to")
	}

	// A day later the host is consulted again; with auto on, the release is installed.
	updateNow = func() time.Time { return time.Date(2026, time.September, 8, 12, 0, 1, 0, time.UTC) }
	if code := runUpdate([]string{"-auto", "on"}); code != exitClean {
		t.Fatalf("auto on = %d", code)
	}
	out.Reset()
	writeUpdateNotice(&out)
	if lookups.Load() != 2 {
		t.Fatalf("lookups after a day = %d", lookups.Load())
	}
	if f.read(t, "skillctl") != "new" || !strings.Contains(out.String(), "updated to 1.2.0") {
		t.Fatalf("auto-update did not install: %q", out.String())
	}

	// Once current, the hook says nothing at all.
	version = "1.2.0"
	out.Reset()
	writeUpdateNotice(&out)
	if out.String() != "" {
		t.Fatalf("an up-to-date binary still speaks: %q", out.String())
	}
}

func TestSessionNoticeIsSilentWhenTheHostIsUnreachableOrDisabled(t *testing.T) {
	f := newUpdateFixture(t)
	releaseBase = "http://127.0.0.1:9" // nothing listens on the discard port
	var out bytes.Buffer
	writeUpdateNotice(&out)
	if out.String() != "" {
		t.Fatalf("an unreachable host produced output: %q", out.String())
	}
	f.serve(t, newFakeRelease(t, "1.2.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("new")}))
	t.Setenv("SKILLTRUST_NO_UPDATE_CHECK", "1")
	writeUpdateNotice(&out)
	if out.String() != "" {
		t.Fatalf("a disabled check produced output: %q", out.String())
	}
}

func TestUpdateCheckReportsWithoutInstalling(t *testing.T) {
	f := newUpdateFixture(t)
	r := newFakeRelease(t, "1.2.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("new")})
	f.serve(t, r)

	var code int
	body := capture(t, func() { code = runUpdate([]string{"-check"}) })
	if code != exitFindings || !strings.Contains(body, "1.2.0 is available") || r.downloads.Load() != 0 {
		t.Fatalf("check = %d %q downloads=%d", code, body, r.downloads.Load())
	}
	// An older "latest" is a rollback, and never an update.
	f.serve(t, newFakeRelease(t, "0.9.0", f.private, map[string][]byte{"skillctl" + exeSuffix(): []byte("old")}))
	body = capture(t, func() { code = runUpdate(nil) })
	if code != exitClean || !strings.Contains(body, "up to date") || f.read(t, "skillctl") != "old skillctl" {
		t.Fatalf("rollback offered: %d %q", code, body)
	}
}
