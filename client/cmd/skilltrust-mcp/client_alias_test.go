package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledCLIUsesAxelaAndSupportsLegacyArchives(t *testing.T) {
	for _, tc := range []struct {
		name, goos, want string
		files            []string
	}{
		{"current macOS", "darwin", "axela", []string{"axela", "skillctl"}},
		{"current Linux", "linux", "axela", []string{"axela", "skillctl"}},
		{"legacy Linux", "linux", "skillctl", []string{"skillctl"}},
		{"current Windows", "windows", "axela.exe", []string{"axela.exe", "skillctl.exe"}},
		{"legacy Windows", "windows", "skillctl.exe", []string{"skillctl.exe"}},
		{"empty bundle", "linux", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("owned release fixture"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			want := tc.want
			if want != "" {
				want = filepath.Join(dir, want)
			}
			if got := bundledCLI(dir, tc.goos); got != want {
				t.Fatalf("bundle chose %q, want %q", got, want)
			}
		})
	}
}

func TestBundledCLIDoesNotRunADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "axela"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skillctl"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := bundledCLI(dir, "linux"); got != filepath.Join(dir, "skillctl") {
		t.Fatalf("expected the executable legacy entry, got %q", got)
	}
}
