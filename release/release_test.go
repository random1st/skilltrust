package release

import (
	"strings"
	"testing"

	"github.com/random1st/skilltrust/attest"
)

const sampleChecksums = "" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  skillctl_1.2.3_darwin_universal.zip\n" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  skillctl_1.2.3_linux_amd64.tar.gz\n"

// The updater trusts the checksums inside the envelope and nothing else, so the
// envelope has to verify only against the release key and carry the text unchanged.
func TestChecksumsRoundTripThroughTheReleaseKey(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignChecksums([]byte(sampleChecksums), private)
	if err != nil {
		t.Fatal(err)
	}
	sums, err := VerifyChecksums(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if sums["skillctl_1.2.3_darwin_universal.zip"] != strings.Repeat("a", 64) || len(sums) != 2 {
		t.Fatalf("checksums = %v", sums)
	}

	stranger, _, _ := attest.GenerateKey()
	if _, err := VerifyChecksums(envelope, attest.NewTrustedKeys(stranger)); err == nil {
		t.Fatal("a signature by another key verified")
	}
	if _, err := SignChecksums([]byte("not a checksums file"), private); err == nil {
		t.Fatal("signed something that is not a checksums file")
	}
}

func TestVersionsCompareAndRefuseWhatIsNotAVersion(t *testing.T) {
	for text, ok := range map[string]bool{"0.4.4": true, "v1.0.0": true, "dev": false, "0.4": false, "v0.4.4-0.20260901-abcdef": false, "1.02.3": false} {
		if _, got := ParseVersion(text); got != ok {
			t.Errorf("ParseVersion(%q) ok = %v, want %v", text, got, ok)
		}
	}
	older, _ := ParseVersion("0.4.4")
	newer, _ := ParseVersion("0.5.0")
	if !newer.Newer(older) || older.Newer(newer) || older.Newer(older) {
		t.Fatal("version ordering is wrong")
	}
}

func TestArchiveNamesMatchTheReleaseConfiguration(t *testing.T) {
	for _, c := range []struct{ goos, goarch, want string }{
		{"darwin", "arm64", "skillctl_0.4.4_darwin_universal.zip"},
		{"darwin", "amd64", "skillctl_0.4.4_darwin_universal.zip"},
		{"linux", "arm64", "skillctl_0.4.4_linux_arm64.tar.gz"},
		{"windows", "amd64", "skillctl_0.4.4_windows_amd64.zip"},
	} {
		got, err := ArchiveName("0.4.4", c.goos, c.goarch)
		if err != nil || got != c.want {
			t.Errorf("%s/%s = %q, %v; want %q", c.goos, c.goarch, got, err, c.want)
		}
	}
	if _, err := ArchiveName("0.4.4", "plan9", "386"); err == nil {
		t.Fatal("an unpublished platform got an archive name")
	}
}
