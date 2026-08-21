// Package skillmd parses SKILL.md against the Agent Skills specification.
//
// The specification (https://agentskills.io/specification) defines exactly six frontmatter
// fields, two of them required. Parse never fails: it collects every deviation as a Defect,
// because the same parser serves the lenient lint path and the strict publishing path and
// only the caller decides what is fatal.
package skillmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Specification limits.
const (
	NameMaxLength          = 64
	DescriptionMaxLength   = 1024
	CompatibilityMaxLength = 500
)

// FileName is the only file the specification requires.
const FileName = "SKILL.md"

// namePattern accepts lowercase alphanumeric segments joined by single hyphens, which
// rejects leading, trailing and consecutive hyphens without a separate check.
var namePattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// SpecFields are the only frontmatter keys the specification defines. Compliant runtimes
// ignore anything else, so unknown keys are reported but never treated as errors.
var SpecFields = map[string]struct{}{
	"name":          {},
	"description":   {},
	"license":       {},
	"compatibility": {},
	"metadata":      {},
	"allowed-tools": {},
}

const delimiter = "---"

// unquotedColon matches the most common cross-client YAML defect: a scalar value that
// contains ": " without being quoted.
var unquotedColon = regexp.MustCompile(`^([A-Za-z][\w-]*):[ \t]+([^"'|>&*!].*:\s.*)$`)

// Defect is a single deviation from the specification, addressed to a human reader.
type Defect struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

// Field is one frontmatter entry with the line it was declared on.
type Field struct {
	Key   string
	Value any
	Line  int
}

// SkillMD is a parsed SKILL.md, however malformed the original was.
//
// FrontmatterStartLine and BodyStartLine are 1-based line numbers *in the file*, so a
// finding in either segment can be reported at a line a reader can actually open. Without
// them a rule scanning the body reports offsets that point nowhere.
type SkillMD struct {
	Path                 string
	Fields               []Field
	Body                 string
	FrontmatterText      string
	FrontmatterStartLine int
	BodyStartLine        int
	Defects              []Defect
	Parsed               bool
}

// Parse reads and parses the file at path.
func Parse(path string) *SkillMD {
	raw, err := os.ReadFile(path)
	if err != nil {
		return &SkillMD{Path: path, Defects: []Defect{{
			Code:    "spec/unreadable",
			Message: fmt.Sprintf("cannot read SKILL.md: %v", err),
		}}}
	}
	if !utf8.Valid(raw) {
		return &SkillMD{Path: path, Defects: []Defect{{
			Code:    "spec/not-utf8",
			Message: "SKILL.md is not valid UTF-8",
		}}}
	}
	return ParseText(path, string(raw))
}

// ParseText parses already-loaded content, so callers can lint archived bytes rather than
// the working tree.
func ParseText(path, text string) *SkillMD {
	var defects []Defect

	if strings.HasPrefix(text, "\uFEFF") {
		defects = append(defects, Defect{
			Code:    "spec/byte-order-mark",
			Message: "file starts with a UTF-8 BOM; strict parsers will not find the opening '---'",
			Line:    1,
		})
		text = strings.TrimPrefix(text, "\uFEFF")
	}

	frontmatter, body, bodyStart, ok := splitFrontmatter(text)
	if !ok {
		defects = append(defects, Defect{
			Code:    "spec/frontmatter-missing",
			Message: "no YAML frontmatter delimited by '---' at the start of the file",
			Line:    1,
		})
		return &SkillMD{Path: path, Body: text, BodyStartLine: 1, Defects: defects}
	}

	fields, loadDefects, loaded := loadFrontmatter(frontmatter)
	defects = append(defects, loadDefects...)
	skill := &SkillMD{
		Path:                 path,
		Fields:               fields,
		Body:                 body,
		FrontmatterText:      frontmatter,
		FrontmatterStartLine: frontmatterLineOffset + 1,
		BodyStartLine:        bodyStart,
		Parsed:               loaded,
	}
	if !loaded {
		skill.Defects = defects
		return skill
	}
	skill.Defects = append(defects, checkFields(skill, path)...)
	return skill
}

// Lookup returns the value declared for key.
func (s *SkillMD) Lookup(key string) (any, int, bool) {
	for _, field := range s.Fields {
		if field.Key == key {
			return field.Value, field.Line, true
		}
	}
	return nil, 0, false
}

// String returns the value of key when it was declared as a string.
func (s *SkillMD) String(key string) (string, bool) {
	value, _, ok := s.Lookup(key)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

// Name returns the declared skill name.
func (s *SkillMD) Name() (string, bool) { return s.String("name") }

// Description returns the declared description.
func (s *SkillMD) Description() (string, bool) { return s.String("description") }

// UnknownFields lists keys outside the specification, in declaration order.
func (s *SkillMD) UnknownFields() []string {
	var unknown []string
	for _, field := range s.Fields {
		if _, ok := SpecFields[field.Key]; !ok {
			unknown = append(unknown, field.Key)
		}
	}
	return unknown
}

// splitFrontmatter returns the frontmatter block, the trimmed body, the 1-based file line
// the body starts on, and whether a complete delimited block was found.
func splitFrontmatter(text string) (string, string, int, bool) {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != delimiter {
		return "", "", 0, false
	}
	for index := 1; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) != delimiter {
			continue
		}
		frontmatter := strings.Join(lines[1:index], "\n")

		// Trimming the body drops leading blank lines, so the offset has to skip them too
		// or every body finding is reported that many lines too early.
		rest := lines[index+1:]
		lead := 0
		for lead < len(rest) && strings.TrimSpace(rest[lead]) == "" {
			lead++
		}
		body := strings.TrimSpace(strings.Join(rest, "\n"))
		return frontmatter, body, index + 2 + lead, true
	}
	return "", "", 0, false
}

// frontmatterLineOffset converts a line number inside the frontmatter block to a line
// number inside the file: line 1 is the opening delimiter.
const frontmatterLineOffset = 1

func loadFrontmatter(text string) ([]Field, []Defect, bool) {
	fields, err := decodeMapping(text)
	if err == nil {
		if fields == nil {
			return nil, []Defect{{
				Code:    "spec/frontmatter-empty",
				Message: "frontmatter block is empty",
				Line:    frontmatterLineOffset + 1,
			}}, false
		}
		return fields, nil, true
	}

	var notMapping *notMappingError
	if asNotMapping(err, &notMapping) {
		return nil, []Defect{{
			Code:    "spec/frontmatter-not-mapping",
			Message: fmt.Sprintf("frontmatter must be a YAML mapping, found %s", notMapping.kind),
			Line:    frontmatterLineOffset + 1,
		}}, false
	}

	repaired, changed := repairUnquotedColons(text)
	if !changed {
		return nil, []Defect{{
			Code:    "spec/frontmatter-unparseable",
			Message: fmt.Sprintf("frontmatter is not valid YAML: %s", oneLine(err)),
			Line:    frontmatterLineOffset + 1,
		}}, false
	}
	fields, repairErr := decodeMapping(repaired)
	if repairErr != nil || fields == nil {
		return nil, []Defect{{
			Code:    "spec/frontmatter-unparseable",
			Message: fmt.Sprintf("frontmatter is not valid YAML: %s", oneLine(err)),
			Line:    frontmatterLineOffset + 1,
		}}, false
	}
	return fields, []Defect{{
		Code: "spec/yaml-repaired",
		Message: "frontmatter is invalid YAML (an unquoted value contains a colon) and was " +
			"only read after repair; strict clients will skip this skill entirely",
		Line: frontmatterLineOffset + 1,
	}}, true
}

type notMappingError struct{ kind string }

func (e *notMappingError) Error() string { return "frontmatter is not a mapping: " + e.kind }

func asNotMapping(err error, target **notMappingError) bool {
	converted, ok := err.(*notMappingError)
	if ok {
		*target = converted
	}
	return ok
}

// decodeMapping preserves declaration order and exact line numbers, which a plain
// map[string]any decode would discard.
func decodeMapping(text string) ([]Field, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		return nil, err
	}
	if len(document.Content) == 0 {
		return nil, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, &notMappingError{kind: nodeKind(root)}
	}

	fields := make([]Field, 0, len(root.Content)/2)
	for index := 0; index+1 < len(root.Content); index += 2 {
		keyNode, valueNode := root.Content[index], root.Content[index+1]
		var value any
		if err := valueNode.Decode(&value); err != nil {
			value = nil
		}
		fields = append(fields, Field{
			Key:   keyNode.Value,
			Value: value,
			Line:  keyNode.Line + frontmatterLineOffset,
		})
	}
	return fields, nil
}

func nodeKind(node *yaml.Node) string {
	switch node.Kind {
	case yaml.SequenceNode:
		return "sequence"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

func repairUnquotedColons(text string) (string, bool) {
	lines := strings.Split(text, "\n")
	changed := false
	for index, line := range lines {
		match := unquotedColon.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value := strings.TrimSpace(match[2])
		if strings.Contains(value, `"`) {
			continue
		}
		lines[index] = fmt.Sprintf("%s: %q", match[1], value)
		changed = true
	}
	return strings.Join(lines, "\n"), changed
}

func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
