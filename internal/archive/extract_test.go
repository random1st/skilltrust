package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtractRoundTripsAFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture depends on the executable bit")
	}

	built, err := Build(buildFixture(t), Limits{})
	if err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(t.TempDir(), "out")
	records, err := ExtractVerified(built.Payload, destination, built.Digest, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(built.Files) {
		t.Fatalf("extracted %d files, packed %d", len(records), len(built.Files))
	}
	for index, record := range records {
		if record != built.Files[index] {
			t.Fatalf("record %d = %+v, want %+v", index, record, built.Files[index])
		}
	}

	info, err := os.Stat(filepath.Join(destination, "scripts", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("the executable bit must survive extraction, or the digest cannot")
	}
}

func TestExtractVerifiedRejectsAMismatchedDigest(t *testing.T) {
	built, err := Build(buildFixture(t), Limits{})
	if err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(t.TempDir(), "out")
	wrong := "sha256:" + strings.Repeat("0", 64)
	if _, err := ExtractVerified(built.Payload, destination, wrong, Limits{}); err == nil {
		t.Fatal("extraction must refuse a payload that is not the verified one")
	}
}

// tarWith builds a deliberately hostile archive. Extraction is where untrusted bytes
// become files, so each of these must be refused rather than merely survived.
func tarWith(t *testing.T, mutate func(*tar.Writer)) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := tar.NewWriter(buffer)
	mutate(writer)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeEntry(t *testing.T, writer *tar.Writer, name string, typeflag byte, body string) {
	t.Helper()
	header := &tar.Header{
		Typeflag: typeflag,
		Name:     name,
		Size:     int64(len(body)),
		Mode:     0o644,
		Format:   tar.FormatPAX,
	}
	if typeflag == tar.TypeSymlink {
		header.Linkname = body
		header.Size = 0
	}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if header.Size > 0 {
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExtractRefusesHostileArchives(t *testing.T) {
	cases := map[string]struct {
		payload []byte
		kind    Kind
	}{
		"path traversal": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "../escaped.md", tar.TypeReg, "x")
			}),
			kind: KindPath,
		},
		"absolute path": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "/etc/passwd", tar.TypeReg, "x")
			}),
			kind: KindPath,
		},
		"symlink": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "link", tar.TypeSymlink, "/etc/passwd")
			}),
			kind: KindEntryType,
		},
		"duplicate member": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "a.md", tar.TypeReg, "one")
				writeEntry(t, w, "a.md", tar.TypeReg, "two")
			}),
			kind: KindCollision,
		},
		"case collision": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "notes/One.md", tar.TypeReg, "one")
				writeEntry(t, w, "notes/one.md", tar.TypeReg, "two")
			}),
			kind: KindCollision,
		},
		"file shadowed by a directory": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "notes", tar.TypeReg, "one")
				writeEntry(t, w, "notes/inner.md", tar.TypeReg, "two")
			}),
			kind: KindCollision,
		},
		"dot segment": {
			payload: tarWith(t, func(w *tar.Writer) {
				writeEntry(t, w, "./a.md", tar.TypeReg, "x")
			}),
			kind: KindPath,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "out")
			_, err := Extract(testCase.payload, destination, Limits{})
			if err == nil {
				t.Fatal("expected a refusal")
			}
			packaging, ok := err.(*Error)
			if !ok || packaging.Kind != testCase.kind {
				t.Fatalf("err = %v, want kind %s", err, testCase.kind)
			}

			// Nothing may have escaped: the parent of the destination stays untouched.
			parent := filepath.Dir(destination)
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "out" {
					t.Fatalf("extraction created %s outside the destination", entry.Name())
				}
			}
		})
	}
}

func TestExtractEnforcesLimits(t *testing.T) {
	payload := tarWith(t, func(w *tar.Writer) {
		writeEntry(t, w, "a.md", tar.TypeReg, strings.Repeat("x", 64))
	})

	destination := filepath.Join(t.TempDir(), "out")
	if _, err := Extract(payload, destination, Limits{MaxFileBytes: 8}); err == nil {
		t.Fatal("expected a per-file limit error")
	}

	many := tarWith(t, func(w *tar.Writer) {
		for index := range 4 {
			writeEntry(t, w, string(rune('a'+index))+".md", tar.TypeReg, "x")
		}
	})
	if _, err := Extract(many, filepath.Join(t.TempDir(), "out"), Limits{MaxFiles: 2}); err == nil {
		t.Fatal("expected a file-count limit error")
	}
}
