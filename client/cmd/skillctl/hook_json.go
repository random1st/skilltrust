package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/random1st/skilltrust/internal/marketplace"
)

// Claude's synchronous command hooks use systemMessage for a user-visible warning.
// No permissionDecision is emitted: successful verification does not override the
// client's normal permission flow. Refusals still exit 2 with a stderr reason.
// https://code.claude.com/docs/en/hooks#json-output
type claudeHookOutput struct {
	SystemMessage      string             `json:"systemMessage,omitempty"`
	HookSpecificOutput *claudeHookContext `json:"hookSpecificOutput,omitempty"`
}

type claudeHookContext struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

func writeClaudeHookJSON(output io.Writer, event, notice string) error {
	notice = visibleHookText(strings.TrimSpace(notice))
	result := claudeHookOutput{SystemMessage: notice}
	if notice != "" {
		result.HookSpecificOutput = &claudeHookContext{HookEventName: event, AdditionalContext: notice}
	}
	return json.NewEncoder(output).Encode(result)
}

// Paths and publisher prose can contain terminal control sequences. Keep intended
// report newlines, but never let an unprintable rune alter the session's display.
func visibleHookText(value string) string {
	var clean strings.Builder
	for _, r := range value {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			clean.WriteRune(r)
		} else {
			fmt.Fprintf(&clean, "\\u%04x", r)
		}
	}
	return clean.String()
}

func writeQuarantineNotice(output io.Writer, result marketplace.Result) {
	diff, adopt := quarantineCommands(result, result.Quarantine, result.OnDisk, "I changed this intentionally")
	if result.Lapsed {
		adopt = nil
	}
	if len(diff) == 0 {
		fmt.Fprintf(output, "  recovery target could not be identified; run %s doctor before choosing a saved copy\n", commandName())
		return
	}
	writeHookCommand(output, "see what changed", diff)
	if len(adopt) > 0 {
		writeHookCommand(output, "to keep your version instead", adopt)
	} else if result.Lapsed {
		fmt.Fprintln(output, "  re-apply your change to the current published version, then adopt that change")
	} else {
		fmt.Fprintln(output, "  inspect the saved copy first; its content digest was not available for an exact approval")
	}
}

func writeHookCommand(output io.Writer, label string, args []string) {
	command := nextCommandText(args)
	if strings.IndexFunc(command, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		fmt.Fprintf(output, "  %s: command arguments (escaped): %q\n", label, args)
		return
	}
	fmt.Fprintf(output, "  %s: %s\n", label, command)
}
