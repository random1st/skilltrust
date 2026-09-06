package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

func TestReleaseAliasesShipTogetherAndReceiveTheSameSigning(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	type build struct {
		ID, Main, Binary                  string
		Env, Flags, Ldflags, Goos, Goarch []string
		Timestamp                         string `yaml:"mod_timestamp"`
	}
	var config struct {
		Project    string `yaml:"project_name"`
		Builds     []build
		Universals []struct {
			ID      string
			IDs     []string
			Replace bool
			Name    string `yaml:"name_template"`
			Hooks   struct{ Post []string }
		} `yaml:"universal_binaries"`
		Archives []struct {
			IDs       []string
			Formats   []string
			Name      string `yaml:"name_template"`
			Overrides []struct {
				Goos    string
				Formats []string
			} `yaml:"format_overrides"`
		}
		Checksum struct {
			Name      string `yaml:"name_template"`
			Algorithm string
		}
		Casks   []struct{ Binaries []string } `yaml:"homebrew_casks"`
		Release struct{ Footer string }
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	builds := map[string]build{}
	for _, item := range config.Builds {
		builds[item.ID] = item
	}
	for _, name := range []string{"axela", "skillctl", "skilltrust-mcp"} {
		item, ok := builds[name]
		if !ok || item.Binary != name || !reflect.DeepEqual(item.Goos, []string{"darwin", "linux", "windows"}) || !reflect.DeepEqual(item.Goarch, []string{"amd64", "arm64"}) {
			t.Fatalf("missing release target for %s: %+v", name, item)
		}
		if !strings.Contains(config.Release.Footer, "codesign --verify --strict -R=notarized --check-notarization "+name+"\n") {
			t.Fatalf("release verification omits %s", name)
		}
		found := false
		for _, universal := range config.Universals {
			if universal.ID != name+"-macos" {
				continue
			}
			found = universal.Replace && universal.Name == name && reflect.DeepEqual(universal.IDs, []string{name}) && reflect.DeepEqual(universal.Hooks.Post, []string{`./scripts/sign-macos.sh "{{ .Path }}"`})
		}
		if !found {
			t.Fatalf("%s misses the signed universal binary", name)
		}
	}
	axela, legacy := builds["axela"], builds["skillctl"]
	axela.ID, axela.Binary = legacy.ID, legacy.Binary
	if axela.Main != "./cmd/skillctl" || !reflect.DeepEqual(axela, legacy) {
		t.Fatalf("Axela must build the identical CLI with identical metadata: %+v vs %+v", axela, legacy)
	}
	wantIDs := []string{"axela", "axela-macos", "skillctl", "skillctl-macos", "skilltrust-mcp", "skilltrust-mcp-macos"}
	if len(config.Archives) != 1 || !slices.Equal(config.Archives[0].IDs, wantIDs) || !slices.Equal(config.Archives[0].Formats, []string{"tar.gz"}) || config.Project != "skillctl" || config.Checksum.Name != "{{ .ProjectName }}_{{ .Version }}_checksums.txt" || config.Checksum.Algorithm != "sha256" {
		t.Fatalf("release names or paired archive changed: %+v", config)
	}
	archiveName, err := template.New("archive").Parse(config.Archives[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ os, arch, want string }{
		{"darwin", "all", "skillctl_1.2.3_darwin_universal"},
		{"linux", "amd64", "skillctl_1.2.3_linux_amd64"},
		{"linux", "arm64", "skillctl_1.2.3_linux_arm64"},
		{"windows", "amd64", "skillctl_1.2.3_windows_amd64"},
		{"windows", "arm64", "skillctl_1.2.3_windows_arm64"},
	} {
		var rendered bytes.Buffer
		if err := archiveName.Execute(&rendered, map[string]string{"ProjectName": config.Project, "Version": "1.2.3", "Os": target.os, "Arch": target.arch}); err != nil {
			t.Fatal(err)
		}
		if rendered.String() != target.want {
			t.Fatalf("archive name changed: %q, want %q", rendered.String(), target.want)
		}
	}
	for _, platform := range []string{"darwin", "windows"} {
		found := false
		for _, format := range config.Archives[0].Overrides {
			if format.Goos == platform && slices.Equal(format.Formats, []string{"zip"}) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s needs its existing zip archive contract", platform)
		}
	}
	if len(config.Casks) != 1 || !slices.Equal(config.Casks[0].Binaries, []string{"axela", "skillctl", "skilltrust-mcp"}) {
		t.Fatalf("cask does not install all executable names: %+v", config.Casks)
	}
}

func TestReleaseAliasUsesExistingMacOSSignAndNotarizeScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release shell scripts run on macOS; fixture uses POSIX sh")
	}
	root := t.TempDir()
	logPath := filepath.Join(root, "calls")
	for _, name := range []string{"codesign", "xcrun"} {
		body := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> \"$AXELA_ALIAS_TEST_LOG\"\n"
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AXELA_ALIAS_TEST_LOG", logPath)
	t.Setenv("APPLE_SIGNING_IDENTITY", "fixture-only")
	t.Setenv("NOTARY_PROFILE", "fixture-only")
	for _, name := range []string{"axela", "skillctl", "skilltrust-mcp"} {
		binary := filepath.Join(root, name)
		if err := os.WriteFile(binary, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", filepath.Join("..", "..", "scripts", "sign-macos.sh"), binary)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sign fixture: %v\n%s", err, output)
		}
	}
	archive := filepath.Join(root, "skillctl_fixture_darwin_universal.zip")
	if err := os.WriteFile(archive, []byte("fixture archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join("..", "..", "scripts", "notarize-macos.sh"), root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("notarize fixture: %v\n%s", err, output)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{}
	for _, name := range []string{"axela", "skillctl", "skilltrust-mcp"} {
		binary := filepath.Join(root, name)
		want = append(want, "codesign --force --sign fixture-only --options runtime --timestamp "+binary, "codesign --verify --strict --verbose=2 "+binary)
	}
	want = append(want, "xcrun notarytool history --keychain-profile fixture-only", "xcrun notarytool submit "+archive+" --keychain-profile fixture-only --wait")
	if string(logged) != strings.Join(want, "\n")+"\n" {
		t.Fatalf("release scripts missed an artifact:\n%s", logged)
	}
}

func TestReleaseAliasesCannotBeShadowedByPluginShims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the canonical plugin guard uses POSIX make")
	}
	makefile, err := filepath.Abs(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "axela", "axela.exe", "axela.cmd", "skillctl", "skillctl.exe", "skillctl.cmd"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for _, directory := range []string{"client", "plugin/bin", "plugin/hooks"} {
				if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "plugin", "hooks", "hooks.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if name != "" {
				if err := os.WriteFile(filepath.Join(root, "plugin", "bin", name), []byte("fixture"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("make", "--no-print-directory", "-f", makefile, "plugin")
			cmd.Dir = filepath.Join(root, "client")
			output, err := cmd.CombinedOutput()
			if name == "" && err != nil || name != "" && (err == nil || !strings.Contains(string(output), name+" shim")) {
				t.Fatalf("plugin guard for %q: %v\n%s", name, err, output)
			}
		})
	}
}
