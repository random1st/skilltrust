// Package lint produces an offline inventory and risk indicators for a tree of Agent Skills.
//
// It reports indicators for human review. A clean report means no indicator fired, never
// that the instructions are benign: no static check can certify prose that an agent will
// follow.
package lint

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/random1st/skilltrust/internal/skillmd"
)

// Scan bounds. Large monorepos must not turn a lint run into a filesystem crawl.
const (
	DefaultMaxDepth       = 6
	DefaultMaxDirectories = 2000
	maxFilesPerSkill      = 2000
)

// Context budgets. The body is loaded whole on activation; the description is loaded at
// startup in every session, for every installed skill.
const (
	BodyTokenBudget        = 5000
	DescriptionTokenBudget = 200
)

// Severity orders findings for reporting and for the --fail-on threshold.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

var severityRank = map[Severity]int{
	SeverityInfo:   0,
	SeverityLow:    1,
	SeverityMedium: 2,
	SeverityHigh:   3,
}

// Rank returns the comparable weight of a severity.
func (s Severity) Rank() int { return severityRank[s] }

// ParseSeverity resolves a --fail-on value.
func ParseSeverity(value string) (Severity, bool) {
	switch Severity(strings.ToLower(value)) {
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityLow:
		return SeverityLow, true
	case SeverityInfo:
		return SeverityInfo, true
	default:
		return "", false
	}
}

// Finding is one indicator, anchored to a file and where possible to a line.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Path     string   `json:"path"`
	Line     int      `json:"line,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
}

// SkillReport is the inventory entry and findings for one skill directory.
type SkillReport struct {
	Name            string    `json:"name,omitempty"`
	Directory       string    `json:"directory"`
	FileCount       int       `json:"file_count"`
	TotalBytes      int64     `json:"total_bytes"`
	ExecutableFiles []string  `json:"executable_files,omitempty"`
	Findings        []Finding `json:"findings,omitempty"`
}

// Report is the result of a whole run.
type Report struct {
	Root     string        `json:"root"`
	Skills   []SkillReport `json:"skills"`
	Findings []Finding     `json:"findings,omitempty"`
	Notes    []string      `json:"notes,omitempty"`
}

// AllFindings returns tree-level findings followed by per-skill findings.
func (r *Report) AllFindings() []Finding {
	all := append([]Finding(nil), r.Findings...)
	for _, skill := range r.Skills {
		all = append(all, skill.Findings...)
	}
	return all
}

// Counts tallies findings by severity.
func (r *Report) Counts() map[Severity]int {
	counts := map[Severity]int{SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0}
	for _, finding := range r.AllFindings() {
		counts[finding.Severity]++
	}
	return counts
}

// Reports is one run: every root that was scanned, and the floor applied to what was
// printed.
//
// It exists because a machine has several skill directories and a check that covers one of
// them describes somewhere the agent is not. The single-Report shape could not express that
// — Root is one string and skill paths are relative to it, so merging roots would mean lying
// in the field a consumer parses to know where a finding lives.
type Reports struct {
	Reports []*Report `json:"reports"`
	// ShownAtOrAbove is the severity floor applied to the findings rendered. The counts are
	// always of everything found: a summary that shrank with the filter would let somebody
	// hide findings from a report by asking to see fewer of them.
	ShownAtOrAbove Severity `json:"shown_at_or_above,omitempty"`
}

// SkillCount is how many skills the run covered, across every root.
func (r Reports) SkillCount() int {
	total := 0
	for _, report := range r.Reports {
		total += len(report.Skills)
	}
	return total
}

// Counts totals every finding in the run, before any display filter.
func (r Reports) Counts() map[Severity]int {
	counts := map[Severity]int{SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0}
	for _, report := range r.Reports {
		for severity, count := range report.Counts() {
			counts[severity] += count
		}
	}
	return counts
}

// AtOrAbove counts findings at or above a severity across the run. This is what --fail-on
// reads, so it must never see the display filter: a tool whose exit code could be quieted by
// asking for less output is one that reports what you asked to hear.
func (r Reports) AtOrAbove(threshold Severity) int {
	total := 0
	for _, report := range r.Reports {
		total += report.AtOrAbove(threshold)
	}
	return total
}

// AtOrAbove counts findings at or above the given severity.
func (r *Report) AtOrAbove(threshold Severity) int {
	count := 0
	for _, finding := range r.AllFindings() {
		if finding.Severity.Rank() >= threshold.Rank() {
			count++
		}
	}
	return count
}

// Options configures a scan.
type Options struct {
	MaxDepth       int
	MaxDirectories int
}

func (o Options) withDefaults() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.MaxDirectories <= 0 {
		o.MaxDirectories = DefaultMaxDirectories
	}
	return o
}

var skippedDirectories = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, ".venv": {}, "venv": {},
	"node_modules": {}, "__pycache__": {}, ".mypy_cache": {}, ".pytest_cache": {},
	".ruff_cache": {}, "dist": {}, "build": {}, ".next": {}, "target": {},
}

// Discover returns directories holding a SKILL.md, plus notes about anything not scanned.
//
// Symlinked directories are followed. Refusing them looked prudent until the tool met a
// real installation: skills arrive from plugin marketplaces as symlinks, and skipping them
// meant seeing 12 skills in a tree of 98 while reporting as though that were all of it. A
// scanner that silently covers an eighth of the target is worse than one that refuses to
// run, because its clean report is believed.
//
// Following a link during discovery is safe in a way that following one during packaging
// is not: here it only decides where to look, while there it would decide which bytes an
// identity covers. archive.Build still refuses every symlink inside a skill.
//
// A skill directory is never descended into: a nested SKILL.md belongs to the bundled
// resources of the outer skill, not to a separate skill.
func Discover(root string, options Options) ([]string, []string) {
	options = options.withDefaults()

	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, []string{root + " is not a directory"}
	}

	var found, notes []string
	visited := 0
	// Keyed by resolved path: a link cycle, or two links onto the same target, must not
	// turn a bounded walk into an unbounded one or report the same skill twice.
	seen := map[string]struct{}{}

	type entry struct {
		path  string
		depth int
	}
	stack := []entry{{path: root}}

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		resolved, err := filepath.EvalSymlinks(current.path)
		if err != nil {
			notes = append(notes, "cannot resolve "+current.path+": "+err.Error())
			continue
		}
		if _, repeat := seen[resolved]; repeat {
			continue
		}
		seen[resolved] = struct{}{}

		visited++
		if visited > options.MaxDirectories {
			notes = append(notes, "stopped after "+itoa(options.MaxDirectories)+
				" directories; the tree may be incomplete")
			break
		}
		if isFile(filepath.Join(current.path, skillmd.FileName)) {
			found = append(found, current.path)
			continue
		}
		if current.depth >= options.MaxDepth {
			notes = append(notes, "stopped at depth "+itoa(options.MaxDepth)+" under "+current.path)
			continue
		}

		children, err := os.ReadDir(current.path)
		if err != nil {
			notes = append(notes, "cannot list "+current.path+": "+err.Error())
			continue
		}
		for index := len(children) - 1; index >= 0; index-- {
			child := children[index]
			path := filepath.Join(current.path, child.Name())
			if _, skip := skippedDirectories[child.Name()]; skip {
				continue
			}
			// Stat rather than trusting the entry type, so a symlink pointing at a
			// directory is followed and one pointing at a file is not.
			target, err := os.Stat(path)
			if err != nil || !target.IsDir() {
				continue
			}
			stack = append(stack, entry{path: path, depth: current.depth + 1})
		}
	}

	sort.Strings(found)
	return found, notes
}

// Run inventories every skill under root and reports specification and risk indicators.
func Run(root string, options Options) *Report {
	directories, notes := Discover(root, options)

	report := &Report{Root: root, Notes: notes, Skills: make([]SkillReport, 0, len(directories))}
	for _, directory := range directories {
		report.Skills = append(report.Skills, lintSkill(directory, root))
	}
	report.Findings = shadowingFindings(report.Skills)
	return report
}

func lintSkill(directory, root string) SkillReport {
	path := filepath.Join(directory, skillmd.FileName)
	parsed := skillmd.Parse(path)
	files, truncated := collectFiles(directory)

	relative := relativeTo(path, root)
	findings := make([]Finding, 0, len(parsed.Defects))
	for _, defect := range parsed.Defects {
		findings = append(findings, Finding{
			Rule:     defect.Code,
			Severity: defectSeverity(defect.Code),
			Message:  defect.Message,
			Path:     relative,
			Line:     defect.Line,
		})
	}
	findings = append(findings, contentFindings(parsed, relative)...)
	findings = append(findings, treeFindings(parsed, files, truncated, directory, root)...)
	findings = append(findings, portabilityFindings(files, root)...)

	var totalBytes int64
	var executables []string
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		totalBytes += info.Size()
		if info.Mode().Perm()&0o111 != 0 {
			executables = append(executables, relativeTo(file, directory))
		}
	}
	sort.Strings(executables)

	name, _ := parsed.Name()
	return SkillReport{
		Name:            name,
		Directory:       relativeTo(directory, root),
		FileCount:       len(files),
		TotalBytes:      totalBytes,
		ExecutableFiles: executables,
		Findings:        findings,
	}
}

func shadowingFindings(skills []SkillReport) []Finding {
	byName := map[string][]string{}
	for _, skill := range skills {
		if skill.Name == "" {
			continue
		}
		byName[skill.Name] = append(byName[skill.Name], skill.Directory)
	}

	names := make([]string, 0, len(byName))
	for name, directories := range byName {
		if len(directories) > 1 {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	findings := make([]Finding, 0, len(names))
	for _, name := range names {
		directories := byName[name]
		sort.Strings(directories)
		findings = append(findings, Finding{
			Rule:     "lint/name-shadowed",
			Severity: SeverityMedium,
			Message: itoa(len(directories)) + " skills declare the name \"" + name +
				"\"; which one loads depends on client-specific precedence, so review " +
				"cannot tell which is active",
			Path:     directories[0],
			Evidence: strings.Join(directories, ", "),
		})
	}
	return findings
}

func collectFiles(directory string) ([]string, bool) {
	var files []string
	truncated := false
	stack := []string{directory}

	for len(stack) > 0 && !truncated {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(current)
		if err != nil {
			continue
		}
		for _, item := range entries {
			if item.Type()&fs.ModeSymlink != 0 {
				continue
			}
			path := filepath.Join(current, item.Name())
			if item.IsDir() {
				if _, skip := skippedDirectories[item.Name()]; !skip {
					stack = append(stack, path)
				}
				continue
			}
			if !item.Type().IsRegular() {
				continue
			}
			if len(files) >= maxFilesPerSkill {
				truncated = true
				break
			}
			files = append(files, path)
		}
	}

	sort.Strings(files)
	return files, truncated
}

var specHighSeverity = map[string]struct{}{
	"spec/name-missing": {}, "spec/description-missing": {}, "spec/description-empty": {},
	"spec/frontmatter-missing": {}, "spec/frontmatter-unparseable": {},
	"spec/frontmatter-not-mapping": {}, "spec/frontmatter-empty": {},
	"spec/not-utf8": {}, "spec/unreadable": {},
}

var specMediumSeverity = map[string]struct{}{
	"spec/angle-brackets": {}, "spec/yaml-repaired": {}, "spec/name-dir-mismatch": {},
}

func defectSeverity(code string) Severity {
	if _, ok := specHighSeverity[code]; ok {
		return SeverityHigh
	}
	if _, ok := specMediumSeverity[code]; ok {
		return SeverityMedium
	}
	return SeverityLow
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func relativeTo(path, base string) string {
	relative, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return relative
}

func estimateTokens(text string) int {
	if text == "" {
		return 0
	}
	if tokens := utf8.RuneCountInString(text) / 4; tokens > 0 {
		return tokens
	}
	return 1
}

func excerpt(text string, limit int) string {
	collapsed := strings.Join(strings.Fields(text), " ")
	if utf8.RuneCountInString(collapsed) <= limit {
		return collapsed
	}
	runes := []rune(collapsed)
	return string(runes[:limit-1]) + "…"
}

func itoa(value int) string { return strconv.Itoa(value) }
