package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func digestOf(t *testing.T, root string) string {
	t.Helper()
	built, err := Build(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return built.Digest
}

// The property the whole design rests on: signing a skill cannot change the skill's
// identity. If writing the envelope moved the digest, the envelope would certify bytes that
// no longer exist the moment it was written.
func TestWritingTheAttestationDoesNotChangeTheDigest(t *testing.T) {
	root := buildFixture(t)
	before := digestOf(t, root)

	write(t, root, AttestationFileName, `{"payloadType":"x","payload":"y","signatures":[]}`, 0o644)
	after := digestOf(t, root)

	if before != after {
		t.Fatalf("digest moved when the attestation was written:\n  before %s\n  after  %s",
			before, after)
	}
}

// Rewriting the envelope must not move the digest either, or every re-signature would
// invalidate itself.
func TestChangingTheAttestationDoesNotChangeTheDigest(t *testing.T) {
	root := buildFixture(t)
	write(t, root, AttestationFileName, "first", 0o644)
	before := digestOf(t, root)

	write(t, root, AttestationFileName, strings.Repeat("second, and much longer", 100), 0o644)
	if after := digestOf(t, root); before != after {
		t.Fatalf("digest moved when the attestation changed:\n  before %s\n  after  %s",
			before, after)
	}
}

// The reserved name is reserved only at the skill root. Deeper in the tree it is ordinary
// content and must be covered, or it would be a second unsigned hole per directory.
func TestTheNameIsOnlyReservedAtTheRoot(t *testing.T) {
	root := buildFixture(t)
	before := digestOf(t, root)

	write(t, root, filepath.ToSlash(filepath.Join("references", AttestationFileName)), "content", 0o644)
	if after := digestOf(t, root); before == after {
		t.Fatal("a file with the reserved name below the root must be signed content")
	}
}

func TestADirectoryAtTheReservedNameIsRefused(t *testing.T) {
	root := buildFixture(t)
	if err := os.MkdirAll(filepath.Join(root, AttestationFileName, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	assertKind(t, root, KindEntryType)
}

// A symlink there would let the excluded path resolve to bytes outside the skill, so it is
// refused rather than followed or quietly skipped.
func TestASymlinkAtTheReservedNameIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := buildFixture(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, AttestationFileName)); err != nil {
		t.Fatal(err)
	}
	assertKind(t, root, KindEntryType)
}

// A near-miss by case would otherwise be packaged as signed content under a name a human
// reads as the signature. Refusing keeps that ambiguity off the filesystem's case rules.
func TestACaseVariantOfTheReservedNameIsRefused(t *testing.T) {
	root := buildFixture(t)
	write(t, root, "Attestation.DSSE.json", "near miss", 0o644)
	assertKind(t, root, KindCollision)
}

// Excluding the attestation must not become a way to smuggle bytes past the digest: what
// lands on extraction is exactly what was signed, and the envelope is not part of it.
func TestTheAttestationIsNotCarriedInTheArchive(t *testing.T) {
	root := buildFixture(t)
	write(t, root, AttestationFileName, "the envelope", 0o644)

	built, err := Build(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range built.Files {
		if file.Path == AttestationFileName {
			t.Fatal("the reserved attestation must not appear as a member of the archive")
		}
	}

	destination := filepath.Join(t.TempDir(), "extracted")
	if _, err := ExtractVerified(built.Payload, destination, built.Digest, Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, AttestationFileName)); !os.IsNotExist(err) {
		t.Fatal("extraction must not produce the attestation; it is not signed content")
	}
}

// A hostile bundle must not be able to supply its own signature slot. Build never emits the
// reserved name, so an archive containing one is malformed by construction; extracting it
// would plant an envelope that a verifier then reads as if it had been found on disk.
func TestAnArchiveCarryingTheReservedNameIsRefused(t *testing.T) {
	hostile := tarWithMembers(t, map[string]string{
		"SKILL.md":          "---\nname: demo\ndescription: A demo skill.\n---\n\nBody.\n",
		AttestationFileName: `{"payloadType":"planted"}`,
	})
	destination := filepath.Join(t.TempDir(), "extracted")

	_, err := Extract(hostile, destination, Limits{})
	if err == nil {
		t.Fatal("an archive containing the reserved attestation must be refused")
	}
	var failure *Error
	if !errorsAs(err, &failure) || failure.Kind != KindEntryType {
		t.Fatalf("err = %v, want a %s failure", err, KindEntryType)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		if entries, _ := os.ReadDir(destination); len(entries) > 0 {
			t.Fatalf("nothing may land from a refused archive, found %d entries", len(entries))
		}
	}
}

// The same name below the root is ordinary signed content and must extract normally.
func TestAnArchiveMayCarryTheNameBelowTheRoot(t *testing.T) {
	fine := tarWithMembers(t, map[string]string{
		"SKILL.md":                          "---\nname: demo\ndescription: A demo skill.\n---\n\nBody.\n",
		"references/" + AttestationFileName: "ordinary content",
	})
	destination := filepath.Join(t.TempDir(), "extracted")
	if _, err := Extract(fine, destination, Limits{}); err != nil {
		t.Fatalf("the reserved name below the root is content, not a reservation: %v", err)
	}
}

func tarWithMembers(t *testing.T, members map[string]string) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := tar.NewWriter(buffer)
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := members[name]
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Size: int64(len(body)),
			Mode: 0o644, Format: tar.FormatPAX, ModTime: zeroTime,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func errorsAs(err error, target **Error) bool { return errors.As(err, target) }
