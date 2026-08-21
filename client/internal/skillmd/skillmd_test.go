package skillmd

import (
	"path/filepath"
	"testing"
)

func parseIn(t *testing.T, directory, text string) *SkillMD {
	t.Helper()
	return ParseText(filepath.Join(t.TempDir(), directory, FileName), text)
}

func codes(skill *SkillMD) map[string]int {
	found := map[string]int{}
	for _, defect := range skill.Defects {
		found[defect.Code]++
	}
	return found
}

func TestParseMinimalValidSkill(t *testing.T) {
	skill := parseIn(t, "pdf-processing", `---
name: pdf-processing
description: Extract text from PDFs. Use when handling PDF documents.
---

# PDF processing
`)

	if !skill.Parsed {
		t.Fatalf("expected a parsed skill, got defects %v", skill.Defects)
	}
	if len(skill.Defects) != 0 {
		t.Fatalf("expected no defects, got %v", skill.Defects)
	}
	if name, _ := skill.Name(); name != "pdf-processing" {
		t.Fatalf("name = %q", name)
	}
	if skill.Body != "# PDF processing" {
		t.Fatalf("body = %q", skill.Body)
	}
}

func TestParseReportsSpecViolations(t *testing.T) {
	cases := []struct {
		name      string
		directory string
		text      string
		want      string
	}{
		{
			name:      "name does not match directory",
			directory: "pdf-tools",
			text:      "---\nname: pdf-processing\ndescription: does things\n---\n",
			want:      "spec/name-dir-mismatch",
		},
		{
			name:      "consecutive hyphens",
			directory: "pdf--processing",
			text:      "---\nname: pdf--processing\ndescription: does things\n---\n",
			want:      "spec/name-invalid",
		},
		{
			name:      "uppercase name",
			directory: "PDF",
			text:      "---\nname: PDF\ndescription: does things\n---\n",
			want:      "spec/name-invalid",
		},
		{
			name:      "missing description",
			directory: "thing",
			text:      "---\nname: thing\n---\n",
			want:      "spec/description-missing",
		},
		{
			name:      "empty description",
			directory: "thing",
			text:      "---\nname: thing\ndescription: \"  \"\n---\n",
			want:      "spec/description-empty",
		},
		{
			name:      "no frontmatter",
			directory: "thing",
			text:      "# just markdown\n",
			want:      "spec/frontmatter-missing",
		},
		{
			name:      "frontmatter is a sequence",
			directory: "thing",
			text:      "---\n- one\n- two\n---\n",
			want:      "spec/frontmatter-not-mapping",
		},
		{
			name:      "metadata values must be strings",
			directory: "thing",
			text:      "---\nname: thing\ndescription: d\nmetadata:\n  version: 1.0\n---\n",
			want:      "spec/metadata-not-string-map",
		},
		{
			// Observed in a real skill: the specification requires a space-separated
			// string, and a YAML sequence silently means something else to every client.
			name:      "allowed-tools as a sequence",
			directory: "thing",
			text:      "---\nname: thing\ndescription: d\nallowed-tools:\n  - Read\n  - Write\n---\n",
			want:      "spec/allowed-tools-not-string",
		},
		{
			name:      "angle brackets in frontmatter",
			directory: "thing",
			text:      "---\nname: thing\ndescription: use <system> tags\n---\n",
			want:      "spec/angle-brackets",
		},
		{
			name:      "byte order mark",
			directory: "thing",
			text:      "\uFEFF---\nname: thing\ndescription: d\n---\n",
			want:      "spec/byte-order-mark",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			skill := parseIn(t, testCase.directory, testCase.text)
			if codes(skill)[testCase.want] == 0 {
				t.Fatalf("expected %s, got %v", testCase.want, skill.Defects)
			}
		})
	}
}

func TestParseRepairsUnquotedColon(t *testing.T) {
	skill := parseIn(t, "thing", `---
name: thing
description: Use this skill when: the user asks about PDFs
---
`)

	if codes(skill)["spec/yaml-repaired"] == 0 {
		t.Fatalf("expected spec/yaml-repaired, got %v", skill.Defects)
	}
	description, ok := skill.Description()
	if !ok || description != "Use this skill when: the user asks about PDFs" {
		t.Fatalf("description = %q ok=%v", description, ok)
	}
}

func TestFieldLinesArePreserved(t *testing.T) {
	skill := parseIn(t, "thing", "---\nname: thing\ndescription: d\nlicense: Apache-2.0\n---\n")

	_, line, ok := skill.Lookup("license")
	if !ok {
		t.Fatal("license not found")
	}
	if line != 4 {
		t.Fatalf("license line = %d, want 4", line)
	}
}

func TestUnknownFieldsAreListedNotRejected(t *testing.T) {
	skill := parseIn(t, "thing", "---\nname: thing\ndescription: d\nzz-custom: v\n---\n")

	if !skill.Parsed {
		t.Fatalf("unknown fields must not stop parsing: %v", skill.Defects)
	}
	unknown := skill.UnknownFields()
	if len(unknown) != 1 || unknown[0] != "zz-custom" {
		t.Fatalf("unknown = %v", unknown)
	}
}
