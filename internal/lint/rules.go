package lint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/random1st/skilltrust/internal/skillmd"
)

// invisibleRunes are characters a reviewer cannot see but the agent still reads. Bidi
// overrides additionally let displayed text differ from executed text.
var invisibleRunes = map[rune]string{
	'\u00AD': "soft hyphen",
	'\u200B': "zero-width space",
	'\u200C': "zero-width non-joiner",
	'\u200D': "zero-width joiner",
	'\u2060': "word joiner",
	'\u2061': "function application",
	'\u2062': "invisible times",
	'\u2063': "invisible separator",
	'\u2064': "invisible plus",
	'\u202A': "bidi left-to-right embedding",
	'\u202B': "bidi right-to-left embedding",
	'\u202C': "bidi pop directional formatting",
	'\u202D': "bidi left-to-right override",
	'\u202E': "bidi right-to-left override",
	'\u2066': "bidi left-to-right isolate",
	'\u2067': "bidi right-to-left isolate",
	'\u2068': "bidi first strong isolate",
	'\u2069': "bidi pop directional isolate",
	'\uFEFF': "zero-width no-break space",
}

// confusableScripts are scripts whose letters render like Latin ones.
var confusableScripts = []struct {
	name  string
	table *unicode.RangeTable
}{
	{"Cyrillic", unicode.Cyrillic},
	{"Greek", unicode.Greek},
}

var (
	htmlComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	// RE2 has no lookaround, so boundaries are checked around the match instead.
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
	urlPattern = regexp.MustCompile("https?://([^\\s/)>\\]\"'`]+)")

	pipeToShell = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k|d)?sh\b`),
		regexp.MustCompile(`(?i)\b(irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}\|\s*(iex|Invoke-Expression)\b`),
	}

	sensitivePaths = []*regexp.Regexp{
		regexp.MustCompile(`(?i)~/\.ssh\b`),
		regexp.MustCompile(`(?i)\bid_rsa\b`),
		regexp.MustCompile(`(?i)\bid_ed25519\b`),
		regexp.MustCompile(`(?i)~/\.aws\b`),
		regexp.MustCompile(`(?i)\.aws/credentials\b`),
		regexp.MustCompile(`\bAWS_SECRET_ACCESS_KEY\b`),
		regexp.MustCompile(`(?i)~/\.netrc\b`),
		regexp.MustCompile(`(?i)\.git-credentials\b`),
		regexp.MustCompile(`(?i)\bsecurity find-generic-password\b`),
		regexp.MustCompile(`\b(GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)\b`),
		regexp.MustCompile(`(?i)(^|[^\w./-])\.env([.][\w-]+)?($|[^\w/])`),
	}

	// negationCue marks a line that forbids rather than instructs. A skill whose text says
	// "never read .env" is the opposite of the threat.
	negationCue = regexp.MustCompile(
		`(?i)\b(never|do not|don't|must not|should not|shouldn't|cannot|can't|avoid|` +
			`refuse|prohibit(ed)?|forbidden|without|no need to)\b`)

	// exfiltrationCue marks a line that tells the agent to *use* the credential rather than
	// merely name it. Mentioning a secret path is unremarkable — a security-audit skill
	// scans for .env, a deploy skill warns about committing one — while reading it and
	// putting it somewhere is the threat.
	//
	// Calibrating the other way round was wrong, and running against a real tree of 97
	// skills proved it: every high-severity credential finding was a security tool doing
	// its job. A linter that flags the audit skill for auditing is one people uninstall,
	// and it takes the true positives with it.
	exfiltrationCue = regexp.MustCompile(
		`(?i)\b(read|cat|open|print|echo|display|show|include|attach|send|post|upload|` +
			`exfiltrat\w*|copy|paste|forward|transmit|report back)\b`)
)

var executableSuffixes = map[string]struct{}{
	".sh": {}, ".bash": {}, ".zsh": {}, ".py": {}, ".rb": {}, ".pl": {},
	".js": {}, ".mjs": {}, ".cjs": {}, ".ts": {}, ".ps1": {}, ".exe": {},
}

// segment is a slice of the file scanned by line-oriented rules, together with the file
// line its first line occupies. Rules must never report an offset into a concatenation of
// frontmatter and body: that number points at no line the reader can open.
type segment struct {
	text string
	base int
}

func contentFindings(parsed *skillmd.SkillMD, path string) []Finding {
	var findings []Finding
	segments := []segment{
		{text: parsed.FrontmatterText, base: parsed.FrontmatterStartLine},
		{text: parsed.Body, base: parsed.BodyStartLine},
	}

	for _, part := range segments {
		if part.text == "" {
			continue
		}
		findings = append(findings, invisibleFindings(part, path)...)
		findings = append(findings, lineProbeFindings(part, path)...)
	}
	findings = append(findings, mixedScriptFindings(parsed, path)...)
	findings = append(findings, htmlCommentFindings(parsed, path)...)
	findings = append(findings, base64Findings(parsed, path)...)
	findings = append(findings, remoteURLFindings(parsed, path)...)
	findings = append(findings, budgetFindings(parsed, path)...)

	return findings
}

func invisibleFindings(part segment, path string) []Finding {
	var findings []Finding
	for number, line := range strings.Split(part.text, "\n") {
		for _, char := range line {
			label, invisible := invisibleRunes[char]
			if !invisible {
				continue
			}
			findings = append(findings, Finding{
				Rule:     "risk/invisible-chars",
				Severity: SeverityHigh,
				Message: fmt.Sprintf(
					"contains an invisible %s (U+%04X); text the reviewer cannot see is text "+
						"the agent still reads", label, char),
				Path:     path,
				Line:     number + 1,
				Evidence: excerpt(line, 100),
			})
			break
		}
	}
	return findings
}

func mixedScriptFindings(parsed *skillmd.SkillMD, path string) []Finding {
	var findings []Finding
	for _, field := range []string{"name", "description"} {
		value, ok := parsed.String(field)
		if !ok {
			continue
		}
		for _, word := range splitWords(value) {
			if !containsScript(word, unicode.Latin) {
				continue
			}
			for _, script := range confusableScripts {
				if !containsScript(word, script.table) {
					continue
				}
				findings = append(findings, Finding{
					Rule:     "risk/mixed-script",
					Severity: SeverityHigh,
					Message: fmt.Sprintf(
						"'%s' mixes Latin and %s letters in %q; this is how a skill "+
							"impersonates another one in the catalog", field, script.name, word),
					Path:     path,
					Evidence: word,
				})
				break
			}
		}
	}
	return findings
}

func htmlCommentFindings(parsed *skillmd.SkillMD, path string) []Finding {
	var findings []Finding
	for _, match := range htmlComment.FindAllStringSubmatchIndex(parsed.Body, -1) {
		comment := strings.TrimSpace(parsed.Body[match[2]:match[3]])
		if comment == "" {
			continue
		}
		findings = append(findings, Finding{
			Rule:     "risk/html-comment",
			Severity: SeverityMedium,
			Message: "HTML comment in the body; it is invisible in rendered markdown but the " +
				"agent reads the raw file",
			Path:     path,
			Line:     bodyLine(parsed, match[0]),
			Evidence: excerpt(comment, 100),
		})
	}
	return findings
}

func base64Findings(parsed *skillmd.SkillMD, path string) []Finding {
	var findings []Finding
	for _, match := range base64Blob.FindAllStringIndex(parsed.Body, -1) {
		if !isolatedMatch(parsed.Body, match[0], match[1]) {
			continue
		}
		findings = append(findings, Finding{
			Rule:     "risk/base64-blob",
			Severity: SeverityMedium,
			Message: fmt.Sprintf("%d-character base64-like blob; opaque to review",
				match[1]-match[0]),
			Path:     path,
			Line:     bodyLine(parsed, match[0]),
			Evidence: excerpt(parsed.Body[match[0]:match[1]], 48),
		})
	}
	return findings
}

func remoteURLFindings(parsed *skillmd.SkillMD, path string) []Finding {
	seen := map[string]struct{}{}
	full := parsed.FrontmatterText + "\n" + parsed.Body
	for _, match := range urlPattern.FindAllStringSubmatch(full, -1) {
		seen[strings.ToLower(match[1])] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	evidence := strings.Join(hosts, ", ")
	if len(hosts) > 8 {
		evidence = strings.Join(hosts[:8], ", ") + " …"
	}
	return []Finding{{
		Rule:     "risk/remote-url",
		Severity: SeverityLow,
		Message: fmt.Sprintf("references %d remote host(s); anything fetched at activation "+
			"time is not covered by the skill's digest", len(hosts)),
		Path:     path,
		Evidence: evidence,
	}}
}

func lineProbeFindings(part segment, path string) []Finding {
	var findings []Finding
	for number, line := range strings.Split(part.text, "\n") {
		for _, pattern := range sensitivePaths {
			if !pattern.MatchString(line) {
				continue
			}
			severity, message := credentialSeverity(line)
			findings = append(findings, Finding{
				Rule:     "risk/credential-path",
				Severity: severity,
				Message:  message,
				Path:     path,
				Line:     part.base + number,
				Evidence: excerpt(line, 100),
			})
			break
		}
		for _, pattern := range pipeToShell {
			if !pattern.MatchString(line) {
				continue
			}
			findings = append(findings, Finding{
				Rule:     "risk/pipe-to-shell",
				Severity: SeverityHigh,
				Message:  "downloads and executes a remote script in one step",
				Path:     path,
				Line:     part.base + number,
				Evidence: excerpt(line, 100),
			})
			break
		}
	}
	return findings
}

// credentialSeverity grades a line that names a credential path by what it asks for.
func credentialSeverity(line string) (Severity, string) {
	switch {
	case negationCue.MatchString(line):
		return SeverityLow, "names a credential file, but the line reads as a prohibition; " +
			"confirm it forbids rather than instructs"
	case exfiltrationCue.MatchString(line):
		return SeverityHigh, "instructs the agent to read or send a credential file or secret"
	default:
		return SeverityLow, "names a credential file or secret environment variable; " +
			"check whether it is being scanned for or reached into"
	}
}

func budgetFindings(parsed *skillmd.SkillMD, path string) []Finding {
	var findings []Finding

	if description, ok := parsed.Description(); ok {
		if tokens := estimateTokens(description); tokens > DescriptionTokenBudget {
			findings = append(findings, Finding{
				Rule:     "risk/context-budget",
				Severity: SeverityLow,
				Message: fmt.Sprintf("description is roughly %d tokens and is loaded at startup "+
					"in every session; the practical budget is about %d",
					tokens, DescriptionTokenBudget),
				Path: path,
			})
		}
	}

	if tokens := estimateTokens(parsed.Body); tokens > BodyTokenBudget {
		findings = append(findings, Finding{
			Rule:     "spec/body-too-large",
			Severity: SeverityLow,
			Message: fmt.Sprintf("body is roughly %d tokens, above the recommended %d; "+
				"move detail into references/", tokens, BodyTokenBudget),
			Path: path,
		})
	}

	return findings
}

func treeFindings(
	parsed *skillmd.SkillMD, files []string, truncated bool, directory, root string,
) []Finding {
	var findings []Finding

	if truncated {
		findings = append(findings, Finding{
			Rule:     "lint/tree-truncated",
			Severity: SeverityInfo,
			Message:  "skill directory was too large to enumerate fully",
			Path:     relativeTo(directory, root),
		})
	}

	for _, file := range files {
		if filepath.Base(file) == skillmd.FileName {
			continue
		}
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		relative := relativeTo(file, root)

		if info.Mode().Perm()&0o111 != 0 {
			findings = append(findings, Finding{
				Rule:     "risk/executable-file",
				Severity: SeverityMedium,
				Message:  "executable file bundled with the skill",
				Path:     relative,
			})
			continue
		}

		_, known := executableSuffixes[strings.ToLower(filepath.Ext(file))]
		if known || hasShebang(file) {
			findings = append(findings, Finding{
				Rule:     "risk/code-without-exec-bit",
				Severity: SeverityMedium,
				Message: "code file without the executable bit; it still runs when invoked by " +
					"an interpreter, so the missing bit does not make the skill instruction-only",
				Path: relative,
			})
		}
	}

	if tools, ok := parsed.String("allowed-tools"); ok && strings.TrimSpace(tools) != "" {
		findings = append(findings, Finding{
			Rule:     "risk/allowed-tools",
			Severity: SeverityMedium,
			Message: "requests pre-approved tools; every listed token runs without a " +
				"confirmation prompt in clients that honour this experimental field",
			Path:     relativeTo(parsed.Path, root),
			Evidence: excerpt(strings.TrimSpace(tools), 120),
		})
	}

	return findings
}

func splitWords(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func containsScript(word string, table *unicode.RangeTable) bool {
	for _, char := range word {
		if unicode.Is(table, char) {
			return true
		}
	}
	return false
}

// isolatedMatch reports whether the match is not part of a longer base64-like run, which
// RE2 cannot express with lookaround.
func isolatedMatch(text string, start, end int) bool {
	if start > 0 && isBase64Byte(text[start-1]) {
		return false
	}
	if end < len(text) && isBase64Byte(text[end]) {
		return false
	}
	return true
}

func isBase64Byte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '+', b == '/', b == '=':
		return true
	default:
		return false
	}
}

func bodyLine(parsed *skillmd.SkillMD, offset int) int {
	return parsed.BodyStartLine + strings.Count(parsed.Body[:offset], "\n")
}

func hasShebang(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	prefix := make([]byte, 2)
	read, err := file.Read(prefix)
	return err == nil && read == 2 && prefix[0] == '#' && prefix[1] == '!'
}
