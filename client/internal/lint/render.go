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
func RenderText(out io.Writer, report *Report) error {
	colors := newPalette(out)
	buffer := &strings.Builder{}

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

		for _, finding := range sortedFindings(skill.Findings) {
			writeFinding(buffer, colors, finding)
		}
		if len(skill.Findings) > 0 {
			buffer.WriteString("\n")
		}
	}

	if len(report.Findings) > 0 {
		fmt.Fprintf(buffer, "  %sacross the tree%s\n", colors.bold, colors.reset)
		for _, finding := range sortedFindings(report.Findings) {
			writeFinding(buffer, colors, finding)
		}
		buffer.WriteString("\n")
	}

	for _, note := range report.Notes {
		fmt.Fprintf(buffer, "  %snote: %s%s\n", colors.dim, note, colors.reset)
	}

	counts := report.Counts()
	fmt.Fprintf(buffer, "%s%d skills · %d high · %d medium · %d low · %d info%s\n",
		colors.bold, len(report.Skills),
		counts[SeverityHigh], counts[SeverityMedium], counts[SeverityLow], counts[SeverityInfo],
		colors.reset)
	fmt.Fprintf(buffer, "%s%s%s\n", colors.dim, Disclaimer, colors.reset)

	_, err := io.WriteString(out, buffer.String())
	return err
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

// RenderJSON writes the machine-readable report.
func RenderJSON(out io.Writer, report *Report) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		*Report
		Disclaimer string `json:"disclaimer"`
	}{Report: report, Disclaimer: Disclaimer})
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

// RenderSARIF writes SARIF 2.1.0 so findings land in GitHub code scanning natively.
func RenderSARIF(out io.Writer, report *Report, version string) error {
	findings := sortedFindings(report.AllFindings())

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
