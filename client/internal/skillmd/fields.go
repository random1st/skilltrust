package skillmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// checkFields validates the parsed frontmatter against the specification. Every deviation
// is returned; nothing short-circuits, because a lint report is more useful than the first
// error.
func checkFields(skill *SkillMD, path string) []Defect {
	var defects []Defect

	defects = append(defects, checkName(skill, path)...)
	defects = append(defects, checkDescription(skill)...)
	defects = append(defects, checkCompatibility(skill)...)
	defects = append(defects, checkMetadata(skill)...)
	defects = append(defects, checkAllowedTools(skill)...)
	defects = append(defects, checkAngleBrackets(skill)...)

	return defects
}

func checkName(skill *SkillMD, path string) []Defect {
	value, line, present := skill.Lookup("name")
	if !present {
		return []Defect{{Code: "spec/name-missing", Message: "required field 'name' is absent"}}
	}
	name, ok := value.(string)
	if !ok {
		return []Defect{{
			Code:    "spec/name-not-string",
			Message: fmt.Sprintf("'name' must be a string, found %s", typeName(value)),
			Line:    line,
		}}
	}

	var defects []Defect
	if length := utf8.RuneCountInString(name); length > NameMaxLength {
		defects = append(defects, Defect{
			Code:    "spec/name-too-long",
			Message: fmt.Sprintf("'name' is %d characters, above the %d limit", length, NameMaxLength),
			Line:    line,
		})
	}
	if !namePattern.MatchString(name) {
		defects = append(defects, Defect{
			Code: "spec/name-invalid",
			Message: fmt.Sprintf(
				"'name' must be lowercase a-z, 0-9 and single hyphens; found %q", name),
			Line: line,
		})
	}
	if directory := filepath.Base(filepath.Dir(path)); name != directory {
		defects = append(defects, Defect{
			Code: "spec/name-dir-mismatch",
			Message: fmt.Sprintf(
				"'name' is %q but the parent directory is %q; strict clients will not load "+
					"this skill", name, directory),
			Line: line,
		})
	}
	return defects
}

func checkDescription(skill *SkillMD) []Defect {
	value, line, present := skill.Lookup("description")
	if !present {
		return []Defect{{
			Code:    "spec/description-missing",
			Message: "required field 'description' is absent; clients skip skills without one",
		}}
	}
	description, ok := value.(string)
	if !ok {
		return []Defect{{
			Code:    "spec/description-not-string",
			Message: fmt.Sprintf("'description' must be a string, found %s", typeName(value)),
			Line:    line,
		}}
	}
	if strings.TrimSpace(description) == "" {
		return []Defect{{
			Code:    "spec/description-empty",
			Message: "'description' is empty; clients skip skills without one",
			Line:    line,
		}}
	}
	if length := utf8.RuneCountInString(description); length > DescriptionMaxLength {
		return []Defect{{
			Code: "spec/description-too-long",
			Message: fmt.Sprintf("'description' is %d characters, above the %d limit",
				length, DescriptionMaxLength),
			Line: line,
		}}
	}
	return nil
}

func checkCompatibility(skill *SkillMD) []Defect {
	value, line, present := skill.Lookup("compatibility")
	if !present {
		return nil
	}
	compatibility, ok := value.(string)
	if !ok {
		return nil
	}
	if length := utf8.RuneCountInString(compatibility); length > CompatibilityMaxLength {
		return []Defect{{
			Code: "spec/compatibility-too-long",
			Message: fmt.Sprintf("'compatibility' is %d characters, above the %d limit",
				length, CompatibilityMaxLength),
			Line: line,
		}}
	}
	return nil
}

func checkMetadata(skill *SkillMD) []Defect {
	value, line, present := skill.Lookup("metadata")
	if !present {
		return nil
	}
	metadata, ok := value.(map[string]any)
	if !ok {
		return []Defect{{
			Code:    "spec/metadata-not-mapping",
			Message: fmt.Sprintf("'metadata' must be a mapping, found %s", typeName(value)),
			Line:    line,
		}}
	}
	var nonStrings []string
	for key, item := range metadata {
		if _, isString := item.(string); !isString {
			nonStrings = append(nonStrings, key)
		}
	}
	if len(nonStrings) == 0 {
		return nil
	}
	sort.Strings(nonStrings)
	return []Defect{{
		Code: "spec/metadata-not-string-map",
		Message: "'metadata' values must be strings; quote these keys: " +
			strings.Join(nonStrings, ", "),
		Line: line,
	}}
}

func checkAllowedTools(skill *SkillMD) []Defect {
	value, line, present := skill.Lookup("allowed-tools")
	if !present {
		return nil
	}
	if _, ok := value.(string); ok {
		return nil
	}
	return []Defect{{
		Code: "spec/allowed-tools-not-string",
		Message: fmt.Sprintf("'allowed-tools' must be a space-separated string, found %s",
			typeName(value)),
		Line: line,
	}}
}

// checkAngleBrackets implements the specification's advice to keep '<' and '>' out of the
// frontmatter, because those values are placed directly into a system prompt.
func checkAngleBrackets(skill *SkillMD) []Defect {
	var defects []Defect
	for _, field := range skill.Fields {
		text, ok := field.Value.(string)
		if !ok || (!strings.ContainsRune(text, '<') && !strings.ContainsRune(text, '>')) {
			continue
		}
		defects = append(defects, Defect{
			Code: "spec/angle-brackets",
			Message: fmt.Sprintf(
				"'%s' contains '<' or '>'; the specification advises against them because "+
					"they can inject markup into the system prompt", field.Key),
			Line: field.Line,
		})
	}
	return defects
}

func typeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int64, uint64:
		return "integer"
	case float64:
		return "number"
	case []any:
		return "sequence"
	case map[string]any:
		return "mapping"
	default:
		return fmt.Sprintf("%T", value)
	}
}
