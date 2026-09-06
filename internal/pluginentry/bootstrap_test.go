package pluginentry

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The transport fixture contains this compiled native test executable, not a
// shell script pretending to be Axela. Actual CLI behavior is tested separately.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "axela" && os.Getenv("AXELA_ENTRY_FIXTURE") == "1" {
		if marker := os.Getenv("AXELA_ENTRY_EXECUTED"); marker != "" {
			if err := os.WriteFile(marker, []byte("native fixture ran\n"), 0o600); err != nil {
				os.Exit(90)
			}
		}
		if len(os.Args) == 3 && os.Args[1] == "doctor" && os.Args[2] == "--help" {
			os.Exit(0)
		}
		if len(os.Args) != 4 || os.Args[1] != "doctor" || os.Args[2] != "--json" || os.Args[3] != "--absolute-commands" {
			os.Exit(91)
		}
		if os.Getenv("AXELA_ENTRY_BAD_JSON") == "1" {
			fmt.Println("not a verdict")
		} else {
			fmt.Println(`{"status":"needs_attention","inventory":{"found":1,"unapproved":1,"skills":[{"name":"review","path":"/fixture/skills/review","verdict":"unapproved"}]}}`)
		}
		code, _ := strconv.Atoi(os.Getenv("AXELA_ENTRY_DOCTOR_EXIT"))
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type fixture struct {
	plugin, data, artifact, requests, executed, platform, format string
	env                                                          []string
	native                                                       []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the plugin entry currently supports macOS and Linux")
	}
	base := t.TempDir()
	f := &fixture{
		plugin: filepath.Join(base, "plugin's source"), data: filepath.Join(base, "current user's data"),
		artifact: filepath.Join(base, "transport-archive"), requests: filepath.Join(base, "requests"),
		executed: filepath.Join(base, "executed"), platform: runtime.GOOS + "_" + runtime.GOARCH, format: "tar.gz",
	}
	if runtime.GOOS == "darwin" {
		f.platform, f.format = "darwin_universal", "zip"
	}
	source := filepath.Join("..", "..", "plugins", "axela")
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(f.plugin, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, body, 0o700)
	})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.native, err = os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	transport := filepath.Join(base, "transport")
	if err := os.Mkdir(transport, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(transport, "curl"), []byte(`#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$AXELA_ENTRY_REQUESTS"
output= url=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
[[ "$url" == "$AXELA_ENTRY_EXPECTED_URL" ]] || exit 92
[[ ${AXELA_ENTRY_OFFLINE:-0} != 1 ]] || exit 7
if [[ ${AXELA_ENTRY_REQUIRE_PROXY:-0} == 1 ]]; then
  [[ ${HTTPS_PROXY:-} == 'http://proxy.fixture:8443' && ${CURL_CA_BUNDLE:-} == "$AXELA_ENTRY_CA" ]] || exit 5
fi
cp "$AXELA_ENTRY_ARTIFACT" "$output"
`), 0o700)
	f.env = []string{
		"PATH=" + transport + ":/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0",
		"AXELA_ENTRY_FIXTURE=1", "AXELA_ENTRY_REQUESTS=" + f.requests,
		"AXELA_ENTRY_ARTIFACT=" + f.artifact, "AXELA_ENTRY_EXECUTED=" + f.executed,
		"AXELA_ENTRY_DOCTOR_EXIT=1", "AXELA_ENTRY_CA=" + filepath.Join(base, "approved-ca.pem"),
		"AXELA_ENTRY_EXPECTED_URL=https://github.com/random1st/skilltrust/releases/download/v0.0.0-local-proof/skillctl_0.0.0-local-proof_" + f.platform + "." + f.format,
	}
	f.pin(t, f.native, 0o700)
	return f
}

func write(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func digest(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func (f *fixture) pin(t *testing.T, binary []byte, mode os.FileMode) {
	t.Helper()
	var archive bytes.Buffer
	if f.format == "zip" {
		writer := zip.NewWriter(&archive)
		header := &zip.FileHeader{Name: "axela", Method: zip.Deflate}
		header.SetMode(mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(binary); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		compressed := gzip.NewWriter(&archive)
		writer := tar.NewWriter(compressed)
		if err := writer.WriteHeader(&tar.Header{Name: "axela", Mode: int64(mode.Perm()), Size: int64(len(binary))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(binary); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write(t, f.artifact, archive.Bytes(), 0o600)
	lock := fmt.Sprintf("0.0.0-local-proof %s %s %s\n", f.platform, digest(archive.Bytes()), digest(binary))
	write(t, filepath.Join(f.plugin, "release.lock"), []byte(lock), 0o600)
}

func (f *fixture) run(script string, extraEnv ...string) (string, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(f.plugin, "scripts", script+".sh"), f.data)
	cmd.Dir = filepath.Dir(f.plugin)
	cmd.Env = append(append([]string{}, f.env...), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return stdout.String(), stderr.String(), exit.ExitCode()
	}
	return stdout.String(), stderr.String() + err.Error(), -1
}

func TestPluginEntryIsExplicitAndUnreleased(t *testing.T) {
	f := newFixture(t)
	lock, err := os.ReadFile(filepath.Join("..", "..", "plugins", "axela", "release.lock"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.plugin, "release.lock"), lock, 0o600)
	out, diagnostics, code := f.run("doctor")
	if code != 2 || out != "" || !strings.Contains(diagnostics, "no published Axela release pinned") {
		t.Fatalf("development entry pretended to be released: %d %s %s", code, out, diagnostics)
	}
	for _, path := range []string{f.data, f.requests, filepath.Join(f.plugin, "bin")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("disabled bootstrap created state, fetched, or shipped PATH entries at %s: %v", path, err)
		}
	}
	skill, err := os.ReadFile(filepath.Join(f.plugin, "skills", "doctor", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"name: doctor", "disable-model-invocation: true", "!`\"${CLAUDE_PLUGIN_ROOT}/scripts/doctor.sh\" \"${CLAUDE_PLUGIN_DATA}\"`"} {
		if !bytes.Contains(skill, []byte(expected)) {
			t.Fatalf("explicit native slash contract lost %q", expected)
		}
	}
}

func TestBootstrapUsesPinnedBytesAndCurrentUserStorageOffline(t *testing.T) {
	f := newFixture(t)
	before, err := os.ReadFile(filepath.Join(f.plugin, "release.lock"))
	if err != nil {
		t.Fatal(err)
	}
	out, diagnostics, code := f.run("bootstrap")
	if code != 0 || diagnostics != "" {
		t.Fatalf("bootstrap failed: %d %s %s", code, out, diagnostics)
	}
	binary := strings.TrimSpace(out)
	want := filepath.Join(f.data, "runtime", "0.0.0-local-proof", f.platform, "axela")
	if binary != want {
		t.Fatalf("runtime escaped current user plugin data: %q", binary)
	}
	body, err := os.ReadFile(binary)
	if err != nil || !bytes.Equal(body, f.native) {
		t.Fatalf("runtime is not the pinned native bytes: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(f.plugin, "release.lock"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("bootstrap changed plugin source: %v", err)
	}
	second, diagnostics, code := f.run("bootstrap", "AXELA_ENTRY_OFFLINE=1")
	if code != 0 || second != out {
		t.Fatalf("verified cache required a network: %d %s %s", code, second, diagnostics)
	}
	requests, err := os.ReadFile(f.requests)
	if err != nil || bytes.Count(requests, []byte("\n")) != 1 {
		t.Fatalf("cached bootstrap fetched again: %v %s", err, requests)
	}
	for _, prohibited := range []string{" --insecure", " -k", "/latest/", "checksums.txt"} {
		if bytes.Contains(requests, []byte(prohibited)) {
			t.Fatalf("bootstrap delegated integrity or weakened TLS: %s", requests)
		}
	}
	for _, required := range []string{"-q ", "--proto =https", "--proto-redir =https", "--max-time 60"} {
		if !bytes.Contains(requests, []byte(required)) {
			t.Fatalf("download lost required option %q: %s", required, requests)
		}
	}
}

func TestBootstrapRejectsBadDownloadsWithoutRunningThem(t *testing.T) {
	for _, scenario := range []string{"corruption", "wrong_binary_hash", "non_executable", "script"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			switch scenario {
			case "corruption":
				write(t, f.artifact, []byte("damaged download"), 0o600)
			case "wrong_binary_hash":
				lock, err := os.ReadFile(filepath.Join(f.plugin, "release.lock"))
				if err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(f.plugin, "release.lock"), []byte(strings.ReplaceAll(string(lock), digest(f.native), strings.Repeat("0", 64))), 0o600)
			case "non_executable":
				f.pin(t, f.native, 0o600)
			case "script":
				f.pin(t, []byte("#!/bin/sh\nexit 0\n"), 0o700)
			}
			out, diagnostics, code := f.run("doctor")
			if code != 2 || out != "" || diagnostics == "" {
				t.Fatalf("bad download became a verdict: %d %s %s", code, out, diagnostics)
			}
			if _, err := os.Lstat(f.executed); !os.IsNotExist(err) {
				t.Fatalf("rejected native payload executed: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(f.data, "runtime", "0.0.0-local-proof", f.platform, "axela")); !os.IsNotExist(err) {
				t.Fatalf("bad payload was activated: %v", err)
			}
		})
	}
}

func TestBootstrapReportsOfflineAndHonorsProxyConfiguration(t *testing.T) {
	f := newFixture(t)
	out, diagnostics, code := f.run("doctor", "AXELA_ENTRY_OFFLINE=1")
	if code != 2 || out != "" || !strings.Contains(diagnostics, "HTTPS_PROXY") {
		t.Fatalf("offline download was not actionable: %d %s %s", code, out, diagnostics)
	}
	_, _, code = f.run("doctor", "AXELA_ENTRY_REQUIRE_PROXY=1")
	if code != 2 {
		t.Fatal("proxy requirement was silently bypassed")
	}
	out, diagnostics, code = f.run("doctor", "AXELA_ENTRY_REQUIRE_PROXY=1", "HTTPS_PROXY=http://proxy.fixture:8443", "CURL_CA_BUNDLE="+filepath.Join(filepath.Dir(f.plugin), "approved-ca.pem"))
	if code != 0 || !strings.Contains(out, `"doctor_exit_code":1`) {
		t.Fatalf("approved proxy/CA configuration was lost: %d %s %s", code, out, diagnostics)
	}
}

func TestBootstrapRechecksTheCachedExecutable(t *testing.T) {
	for _, damage := range []string{"bytes", "permission"} {
		t.Run(damage, func(t *testing.T) {
			f := newFixture(t)
			out, diagnostics, code := f.run("bootstrap")
			if code != 0 {
				t.Fatalf("initial bootstrap: %s %s", out, diagnostics)
			}
			binary := strings.TrimSpace(out)
			if damage == "bytes" {
				write(t, binary, []byte("changed"), 0o700)
			} else if err := os.Chmod(binary, 0o600); err != nil {
				t.Fatal(err)
			}
			out, diagnostics, code = f.run("doctor", "AXELA_ENTRY_OFFLINE=1")
			if code != 2 || out != "" || !strings.Contains(diagnostics, "no skill check ran") {
				t.Fatalf("damaged cache yielded a verdict: %d %s %s", code, out, diagnostics)
			}
		})
	}
}

func TestDoctorPreservesTheExitCodeWithoutMaskingFailures(t *testing.T) {
	for _, expected := range []int{0, 1, 2, 126} {
		t.Run(strconv.Itoa(expected), func(t *testing.T) {
			f := newFixture(t)
			out, diagnostics, code := f.run("doctor", "AXELA_ENTRY_DOCTOR_EXIT="+strconv.Itoa(expected))
			if expected > 1 {
				if code != expected || out != "" || !strings.Contains(diagnostics, "doctor failed") {
					t.Fatalf("unexpected failure was masked: %d %s %s", code, out, diagnostics)
				}
				return
			}
			var result struct {
				Exit   int `json:"doctor_exit_code"`
				Result struct {
					Status string `json:"status"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(out), &result); err != nil || code != 0 || result.Exit != expected || result.Result.Status != "needs_attention" {
				t.Fatalf("finding did not reach the slash result: %d %s %s (%v)", code, out, diagnostics, err)
			}
		})
	}
	f := newFixture(t)
	out, _, code := f.run("doctor", "AXELA_ENTRY_BAD_JSON=1")
	if code != 2 || out != "" {
		t.Fatalf("missing JSON became a successful invocation: %d %s", code, out)
	}
}

func TestConcurrentBootstrapNeverPublishesPartialBytes(t *testing.T) {
	f := newFixture(t)
	const callers = 6
	type response struct {
		out, diagnostics string
		code             int
	}
	results := make(chan response, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			out, diagnostics, code := f.run("doctor")
			results <- response{out, diagnostics, code}
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		if result.code != 0 || !json.Valid([]byte(result.out)) || !strings.Contains(result.out, `"doctor_exit_code":1`) {
			t.Fatalf("concurrent bootstrap exposed incomplete state: %+v", result)
		}
	}
	storage := filepath.Join(f.data, "runtime", "0.0.0-local-proof", f.platform)
	entries, err := os.ReadDir(storage)
	if err != nil || len(entries) != 1 || entries[0].Name() != "axela" {
		t.Fatalf("bootstrap left partial activation state: %+v %v", entries, err)
	}
	body, err := os.ReadFile(filepath.Join(storage, "axela"))
	if err != nil || !bytes.Equal(body, f.native) {
		t.Fatalf("concurrent callers changed pinned bytes: %v", err)
	}
}

func TestBootstrapRejectsSymlinkedUserStorage(t *testing.T) {
	f := newFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, f.data); err != nil {
		t.Fatal(err)
	}
	out, diagnostics, code := f.run("doctor")
	if code != 2 || out != "" || !strings.Contains(diagnostics, "symbolic link") {
		t.Fatalf("storage link was followed: %d %s %s", code, out, diagnostics)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("bootstrap wrote outside plugin data: %v %v", entries, err)
	}
}
