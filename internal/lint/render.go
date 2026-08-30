package lint

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Disclaimer is printed with every report. A clean run means no indicator fired, which is
// not the same as a safety verdict, and the tool must never let a reader confuse the two.
const Disclaimer = "Indicators for human review. A clean report is not a safety verdict: " +
	"no static check can certify prose that an agent will follow."

type palette struct{ reset, bold, dim, red, yellow, blue, green string }

func newPalette(out io.Writer) palette {
	if os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	file, ok := out.(*os.File)
	if !ok {
		return palette{}
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return palette{}
	}
	return palette{
		reset: "\033[0m", bold: "\033[1m", dim: "\033[2m",
		red: "\033[31m", yellow: "\033[33m", blue: "\033[34m", green: "\033[32m",
	}
}

func (p palette) forSeverity(severity Severity) string {
	switch severity {
	case SeverityHigh:
		return p.red
	case SeverityMedium:
		return p.yellow
	case SeverityLow:
		return p.blue
	default:
		return p.dim
	}
}

// RenderText writes the human-facing report.
// RenderText writes one root's report with its own summary. Kept for a caller that has a
// single Report in hand; a whole run goes through RenderTextAll.
func RenderText(out io.Writer, report *Report) error {
	return RenderTextAll(out, Reports{Reports: []*Report{report}})
}

// RenderTextAll writes every root that was scanned, then one summary for the run.
//
// One summary, not one per root: the question is "is anything wrong on this machine", and
// four totals to add up by hand is how a reader picks the first one and stops.
func RenderTextAll(out io.Writer, reports Reports) error {
	colors := newPalette(out)
	buffer := &strings.Builder{}

	for _, report := range reports.Reports {
		writeReportBody(buffer, colors, report, reports.ShownAtOrAbove)
	}

	counts := reports.Counts()
	fmt.Fprintf(buffer, "%s%d skills · %d high · %d medium · %d low · %d info%s",
		colors.bold, reports.SkillCount(),
		counts[SeverityHigh], counts[SeverityMedium], counts[SeverityLow], counts[SeverityInfo],
		colors.reset)
	if roots := len(reports.Reports); roots > 1 {
		fmt.Fprintf(buffer, "%s  across %d directories%s", colors.dim, roots, colors.reset)
	}
	buffer.WriteString("\n")

	// Said whenever a filter is on, because the counts above are of everything found and the
	// list is not. Without this line the two disagree and the reader trusts the shorter one.
	if hidden := hiddenCount(reports); hidden > 0 {
		fmt.Fprintf(buffer, "%s%d finding(s) below %s were counted but not listed; "+
			"pass --min-severity info to see them%s\n",
			colors.dim, hidden, reports.ShownAtOrAbove, colors.reset)
	}
	fmt.Fprintf(buffer, "%s%s%s\n", colors.dim, Disclaimer, colors.reset)

	_, err := io.WriteString(out, buffer.String())
	return err
}

func hiddenCount(reports Reports) int {
	if reports.ShownAtOrAbove == "" {
		return 0
	}
	hidden := 0
	for _, report := range reports.Reports {
		for _, finding := range report.AllFindings() {
			if finding.Severity.Rank() < reports.ShownAtOrAbove.Rank() {
				hidden++
			}
		}
	}
	return hidden
}

// keep returns the findings at or above the floor, in display order.
func keep(findings []Finding, floor Severity) []Finding {
	sorted := sortedFindings(findings)
	if floor == "" {
		return sorted
	}
	kept := make([]Finding, 0, len(sorted))
	for _, finding := range sorted {
		if finding.Severity.Rank() >= floor.Rank() {
			kept = append(kept, finding)
		}
	}
	return kept
}

func writeReportBody(buffer *strings.Builder, colors palette, report *Report, floor Severity) {
	fmt.Fprintf(buffer, "%sskillctl lint%s  %s\n\n", colors.bold, colors.reset, report.Root)

	if len(report.Skills) == 0 {
		fmt.Fprintf(buffer, "  no SKILL.md found\n\n")
	}

	for _, skill := range report.Skills {
		name := skill.Name
		if name == "" {
			name = "(unnamed)"
		}
		marker, markerColor := "ok", colors.green
		if worst, ok := worstOf(skill.Findings); ok {
			marker, markerColor = string(worst), colors.forSeverity(worst)
		}
		fmt.Fprintf(buffer, "  %s%-6s%s %s%-32s%s %s%s · %d files · %s%s\n",
			markerColor, marker, colors.reset,
			colors.bold, name, colors.reset,
			colors.dim, skill.Directory, skill.FileCount, humanBytes(skill.TotalBytes), colors.reset)

		shown := keep(skill.Findings, floor)
		for _, finding := range shown {
			writeFinding(buffer, colors, finding)
		}
		if len(shown) > 0 {
			buffer.WriteString("\n")
		}
	}

	if shown := keep(report.Findings, floor); len(shown) > 0 {
		fmt.Fprintf(buffer, "  %sacross the tree%s\n", colors.bold, colors.reset)
		for _, finding := range shown {
			writeFinding(buffer, colors, finding)
		}
		buffer.WriteString("\n")
	}

	// Notes survive the filter. They are not findings — they are what the walk could not do,
	// and a scan that hit a permission error must say so however quiet you asked it to be.
	for _, note := range report.Notes {
		fmt.Fprintf(buffer, "  %snote: %s%s\n", colors.dim, note, colors.reset)
	}
}

func writeFinding(buffer *strings.Builder, colors palette, finding Finding) {
	location := finding.Path
	if finding.Line > 0 {
		location = fmt.Sprintf("%s:%d", finding.Path, finding.Line)
	}
	fmt.Fprintf(buffer, "      %s%-6s%s %-26s %s%s%s\n",
		colors.forSeverity(finding.Severity), finding.Severity, colors.reset,
		finding.Rule, colors.dim, location, colors.reset)
	fmt.Fprintf(buffer, "             %s\n", finding.Message)
	if finding.Evidence != "" {
		fmt.Fprintf(buffer, "             %s> %s%s\n", colors.dim, finding.Evidence, colors.reset)
	}
}

func sortedFindings(findings []Finding) []Finding {
	sorted := append([]Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity.Rank() != sorted[j].Severity.Rank() {
			return sorted[i].Severity.Rank() > sorted[j].Severity.Rank()
		}
		if sorted[i].Path != sorted[j].Path {
			return sorted[i].Path < sorted[j].Path
		}
		return sorted[i].Line < sorted[j].Line
	})
	return sorted
}

func worstOf(findings []Finding) (Severity, bool) {
	if len(findings) == 0 {
		return "", false
	}
	worst := findings[0].Severity
	for _, finding := range findings[1:] {
		if finding.Severity.Rank() > worst.Rank() {
			worst = finding.Severity
		}
	}
	return worst, true
}

func humanBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGT"[exp])
}

// RenderJSON writes one root, for a caller holding a single Report.
func RenderJSON(out io.Writer, report *Report) error {
	return RenderJSONAll(out, Reports{Reports: []*Report{report}})
}

// RenderJSONAll writes the whole run.
//
// The shape is an object with a reports array rather than a bare report, and that is a
// change consumers see. It is the honest one: a machine has several skill directories, and
// the old shape could name only one root while implying it was the whole answer. The
// alternative — merging roots into a single Report — would have put a Root in the document
// that half the paths inside it are not relative to.
func RenderJSONAll(out io.Writer, reports Reports) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Reports
		Disclaimer string `json:"disclaimer"`
	}{Reports: reports, Disclaimer: Disclaimer})
}

// SARIF types, limited to the subset GitHub code scanning consumes.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifText         `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// RenderSARIF writes SARIF 2.1.0 for one root.
func RenderSARIF(out io.Writer, report *Report, version string) error {
	return RenderSARIFAll(out, Reports{Reports: []*Report{report}}, version)
}

// RenderSARIFAll writes every root as one run.
//
// SARIF carries a runs array natively, so several roots need no invented wrapper here. The
// display filter is deliberately not applied: this file is read by code scanning, not by a
// person with a context window, and quietly dropping findings from the artefact an audit
// reads would be the worst place in this tool to save space.
func RenderSARIFAll(out io.Writer, reports Reports, version string) error {
	var all []Finding
	for _, report := range reports.Reports {
		all = append(all, report.AllFindings()...)
	}
	findings := sortedFindings(all)

	ruleIndex := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		if _, seen := ruleIndex[finding.Rule]; !seen {
			ruleIndex[finding.Rule] = sarifRule{
				ID:               finding.Rule,
				ShortDescription: sarifText{Text: finding.Rule},
				Properties: map[string]string{
					"security-severity": securitySeverity(finding.Severity),
				},
			}
		}
		location := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: toURI(finding.Path)},
		}}
		if finding.Line > 0 {
			location.PhysicalLocation.Region = &sarifRegion{StartLine: finding.Line}
		}
		results = append(results, sarifResult{
			RuleID:    finding.Rule,
			Level:     sarifLevel(finding.Severity),
			Message:   sarifText{Text: finding.Message},
			Locations: []sarifLocation{location},
		})
	}

	ruleIDs := make([]string, 0, len(ruleIndex))
	for id := range ruleIndex {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, ruleIndex[id])
	}

	document := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "skillctl",
				Version:        version,
				InformationURI: "https://agentskills.io/specification",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func sarifLevel(severity Severity) string {
	switch severity {
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps to the CVSS-like scale GitHub uses to bucket alerts.
func securitySeverity(severity Severity) string {
	switch severity {
	case SeverityHigh:
		return "7.5"
	case SeverityMedium:
		return "5.0"
	case SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func toURI(path string) string {
	return strings.ReplaceAll(path, string(os.PathSeparator), "/")
}
