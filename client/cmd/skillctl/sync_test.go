package main

import (
	"os"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/internal/marketplace"
)

// capture runs f with stdout redirected and returns what it printed.
func capture(t *testing.T, f func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	done := make(chan string, 1)
	go func() {
		var builder strings.Builder
		buffer := make([]byte, 4096)
		for {
			n, err := read.Read(buffer)
			if n > 0 {
				builder.Write(buffer[:n])
			}
			if err != nil {
				break
			}
		}
		done <- builder.String()
	}()

	f()
	write.Close()
	os.Stdout = original
	return <-done
}

// A marketplace nobody could read contributes zero to every count, so the summary of a
// failed run is character-for-character the summary of a clean one — and it is the last
// thing on screen, which is the part people read. The run must end by saying what it did
// not check, not by showing reassuring zeros.
func TestAnUnreadableMarketplaceIsNotReportedAsNothingToDo(t *testing.T) {
	output := capture(t, func() {
		writeReconcileReport(nil, []string{"acme: cannot fetch the catalog index"}, t.TempDir(), false)
	})

	if !strings.Contains(output, "could not be read") {
		t.Fatalf("the summary hides the failure:\n%s", output)
	}
	// The caveat has to come after the counts it invalidates; above them it is the line
	// people scroll past.
	counts := strings.Index(output, "0 verified")
	caveat := strings.Index(output, "could not be read")
	if counts < 0 || caveat < counts {
		t.Fatalf("the caveat must follow the counts:\n%s", output)
	}
}

// The exit code is what a script reads, and an unreadable marketplace is not success.
func TestAnUnreadableMarketplaceIsAnError(t *testing.T) {
	var code int
	capture(t, func() {
		code = writeReconcileReport(nil, []string{"acme: unreachable"}, t.TempDir(), false)
	})
	if code == exitClean {
		t.Fatal("a run that checked nothing must not exit clean")
	}
}

// A run that genuinely had nothing to do says so without a caveat that would train
// readers to ignore it.
func TestACleanRunCarriesNoCaveat(t *testing.T) {
	output := capture(t, func() {
		writeReconcileReport(
			[]marketplace.Result{{Outcome: marketplace.OutcomeVerified, Plugin: "delegate"}},
			nil, t.TempDir(), false)
	})

	if strings.Contains(output, "could not be read") {
		t.Fatalf("a clean run warns about nothing:\n%s", output)
	}
	if !strings.Contains(output, "1 verified") {
		t.Fatalf("the clean summary is wrong:\n%s", output)
	}
}
