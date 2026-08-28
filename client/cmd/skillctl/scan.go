package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A signature proves who published bytes and that they have not changed. It has never
// said anything about what those bytes do, and this file is where that gap is narrowed —
// not closed. Scanning reads a skill and reports what it finds; it cannot prove a skill
// is safe, and a publisher who signs a scanned skill is still vouching for their own
// judgement, not delegating it.
//
// The scanner is NVIDIA SkillSpector (Apache-2.0), invoked rather than vendored: it is a
// Python program with its own release cadence and rule updates, and a copy frozen inside
// this binary would be a stale copy the day after it shipped. When it is absent, that is
// reported as "not scanned" — never as a pass.
const scannerBinary = "skillspector"

// ErrScannerMissing is a scanner that is not installed, which is different from a scan
// that found nothing: one is an unanswered question, the other is an answer.
var ErrScannerMissing = errors.New("skillspector is not installed")

// scanVerdict is the part of a SkillSpector report this tool acts on. The full report is
// richer and is kept for the operator to read; what a gate needs is the recommendation,
// the score, and enough of the findings to say why.
type scanVerdict struct {
	Skill          string
	Score          int
	Recommendation string
	Severities     map[string]int
	Findings       []scanFinding
	// LLMUsed records whether the semantic pass ran. A static-only scan is a complete
	// answer to a narrower question, and reporting it as though the deeper one ran would
	// be the overstatement this project exists to avoid.
	LLMUsed bool
	Raw     []byte
}

type scanFinding struct {
	Severity string
	Category string
	File     string
	Line     int
	Detail   string
}

// Blocks reports whether this verdict should stop a signature. Only the scanner's own
// top recommendation blocks: a tool that re-derives its own thresholds from someone
// else's scores ends up disagreeing with the report it prints.
func (v scanVerdict) Blocks() bool { return v.Recommendation == "DO_NOT_INSTALL" }

// scanSkill runs the scanner over one directory and parses its report.
//
// A non-zero exit is not an error: SkillSpector exits 1 for "do not install", which is a
// verdict, not a failure. Exit 2 is the failure, and so is a report that will not parse —
// both leave the question unanswered, which the caller must not read as a pass.
func scanSkill(directory string, useLLM bool) (scanVerdict, error) {
	binary, err := exec.LookPath(scannerBinary)
	if err != nil {
		return scanVerdict{}, ErrScannerMissing
	}

	report, err := os.CreateTemp("", "skillspector-*.json")
	if err != nil {
		return scanVerdict{}, err
	}
	report.Close()
	defer os.Remove(report.Name())

	args := []string{"scan", directory, "-f", "json", "-o", report.Name()}
	if !useLLM {
		args = append(args, "--no-llm")
	}
	// The scanner logs a line per skipped analyzer, so signing eleven plugins buries the
	// verdict under a hundred warnings and the one line that matters goes unread. Hold its
	// diagnostics and print them only when there is no report to explain what went wrong.
	var diagnostics bytes.Buffer
	command := exec.Command(binary, args...)
	command.Stderr = &diagnostics
	runErr := command.Run()

	body, readErr := os.ReadFile(report.Name())
	if readErr != nil || len(body) == 0 {
		os.Stderr.Write(diagnostics.Bytes())
		if runErr != nil {
			return scanVerdict{}, fmt.Errorf("%s wrote no report: %w", scannerBinary, runErr)
		}
		return scanVerdict{}, fmt.Errorf("%s wrote no report", scannerBinary)
	}
	verdict, err := parseScanReport(body)
	if err != nil {
		return scanVerdict{}, err
	}
	verdict.Skill = filepath.Base(directory)
	return verdict, nil
}

// parseScanReport reads the fields this tool acts on out of a SkillSpector report. It is
// deliberately tolerant of fields it does not know: the scanner's schema will grow, and a
// gate that refuses to run because a new key appeared is a gate people disable.
func parseScanReport(body []byte) (scanVerdict, error) {
	var report struct {
		RiskAssessment struct {
			Score          int    `json:"score"`
			Recommendation string `json:"recommendation"`
		} `json:"risk_assessment"`
		Metadata struct {
			LLMAvailable bool `json:"llm_available"`
		} `json:"metadata"`
		Issues []struct {
			Severity    string `json:"severity"`
			Category    string `json:"category"`
			Finding     string `json:"finding"`
			Explanation string `json:"explanation"`
			Location    struct {
				File      string `json:"file"`
				StartLine int    `json:"start_line"`
			} `json:"location"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		return scanVerdict{}, fmt.Errorf("the scan report is not readable: %w", err)
	}
	if report.RiskAssessment.Recommendation == "" {
		return scanVerdict{}, fmt.Errorf("the scan report carries no recommendation")
	}

	verdict := scanVerdict{
		Score:          report.RiskAssessment.Score,
		Recommendation: report.RiskAssessment.Recommendation,
		Severities:     map[string]int{},
		LLMUsed:        report.Metadata.LLMAvailable,
		Raw:            body,
	}
	for _, issue := range report.Issues {
		verdict.Severities[issue.Severity]++
		detail := issue.Finding
		if detail == "" {
			detail = issue.Explanation
		}
		verdict.Findings = append(verdict.Findings, scanFinding{
			Severity: issue.Severity, Category: issue.Category,
			File: issue.Location.File, Line: issue.Location.StartLine,
			Detail: strings.TrimSpace(firstLine(detail)),
		})
	}
	return verdict, nil
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return text[:index]
	}
	return text
}

// printVerdict writes the human summary. Severity counts first, because that is what an
// operator reads; the findings follow for the one who is deciding whether to override.
func printVerdict(verdict scanVerdict) {
	depth := "static analysis only"
	if verdict.LLMUsed {
		depth = "static and semantic analysis"
	}
	fmt.Printf("%-11s %s\n", "scanned", verdict.Skill)
	fmt.Printf("%-11s %d — %s (%s)\n", "score", verdict.Score, verdict.Recommendation, depth)

	if len(verdict.Findings) == 0 {
		fmt.Printf("%-11s nothing the scanner recognises\n", "findings")
		return
	}
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	var counts []string
	for _, severity := range order {
		if n := verdict.Severities[severity]; n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", n, strings.ToLower(severity)))
		}
	}
	fmt.Printf("%-11s %s\n", "findings", strings.Join(counts, ", "))

	shown := verdict.Findings
	sort.SliceStable(shown, func(i, j int) bool {
		return severityRank(shown[i].Severity) < severityRank(shown[j].Severity)
	})
	for index, finding := range shown {
		if index == 8 {
			fmt.Printf("            … %d more in the full report\n", len(shown)-8)
			break
		}
		where := finding.File
		if finding.Line > 0 {
			where = fmt.Sprintf("%s:%d", where, finding.Line)
		}
		fmt.Printf("  %-8s %s\n", finding.Severity, where)
		if finding.Detail != "" {
			fmt.Printf("           %s\n", finding.Detail)
		}
	}
}

func severityRank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

func runScan(args []string) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl scan [flags] <directory>\n\n"+
			"Reads a skill and reports what a scanner finds in it, before you sign it or\n"+
			"install it. This asks a different question from every other command here:\n"+
			"a signature says who published bytes, a scan says what those bytes appear to do.\n"+
			"Neither proves a skill is safe.\n\n"+
			"Uses NVIDIA SkillSpector (Apache-2.0), which must be installed:\n"+
			"  uv tool install git+https://github.com/NVIDIA/skillspector.git\n\n"+
			"Static analysis runs locally and sends nothing anywhere. --llm adds a semantic\n"+
			"pass that transmits file contents to whichever model provider you configured.\n\n"+
			"Exit codes: %d nothing blocking, %d the scanner says do not install, %d error.\n\nFlags:\n",
			exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}
	useLLM := flags.Bool("llm", false,
		"also run the scanner's semantic pass, which sends file contents to your configured model provider")
	output := flags.String("report", "", "write the scanner's full JSON report here")

	if err := parseArgs(flags, args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsage
	}

	verdict, err := scanSkill(flags.Arg(0), *useLLM)
	if errors.Is(err, ErrScannerMissing) {
		fmt.Fprintf(os.Stderr, "skillctl: %s is not installed, so nothing was scanned. "+
			"Install it with:\n  uv tool install git+https://github.com/NVIDIA/skillspector.git\n",
			scannerBinary)
		return exitUsage
	}
	if err != nil {
		return fail(err)
	}

	printVerdict(verdict)
	if *output != "" {
		if err := os.WriteFile(*output, verdict.Raw, 0o644); err != nil {
			return fail(err)
		}
		fmt.Printf("%-11s %s\n", "report", *output)
	}
	if verdict.Blocks() {
		return exitFindings
	}
	return exitClean
}

// scanBeforeSigning runs the gate every publisher path shares. It returns the skills the
// scanner refused, so the caller can name them rather than failing with a count.
//
// A missing scanner is reported once and does not block: making the signing path depend
// on a Python tool being installed would turn "sign your marketplace" into a support
// burden, and a gate people cannot run is a gate they route around. What it must never do
// is stay quiet — an unscanned publication says so on the way out.
func scanBeforeSigning(directories []string, useLLM bool, now time.Time) (blocked []scanVerdict, ran bool) {
	for _, directory := range directories {
		verdict, err := scanSkill(directory, useLLM)
		if errors.Is(err, ErrScannerMissing) {
			return nil, false
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillctl: %s could not be scanned: %v\n",
				filepath.Base(directory), err)
			continue
		}
		ran = true
		if verdict.Blocks() {
			blocked = append(blocked, verdict)
		}
	}
	return blocked, ran
}
