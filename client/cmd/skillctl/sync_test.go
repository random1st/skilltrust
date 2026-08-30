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

// Found by using the tool rather than by reading it. A machine following two catalogs that
// sign sixteen plugins between them, with none of the sixteen installed, was told:
//
//	16 signed plugins · 0 verified · 0 needing attention
//
// Every figure correct, and the line reads as a clean verification of sixteen things. It is
// the same failure the unreadable-marketplace test above exists for — a run that verified
// nothing looking exactly like a run where nothing was wrong — fixed there and missed here.
func TestPluginsThatAreNotInstalledAreNotReportedAsVerified(t *testing.T) {
	absent := make([]marketplace.Result, 16)
	for i := range absent {
		absent[i] = marketplace.Result{Outcome: marketplace.OutcomeAbsent, Plugin: "signed-elsewhere"}
	}

	output := capture(t, func() {
		writeReconcileReport(absent, nil, t.TempDir(), false)
	})

	if !strings.Contains(output, "16 not installed here") {
		t.Errorf("the counts must add up to the first number:\n%s", output)
	}
	if !strings.Contains(output, "Nothing was verified") {
		t.Errorf("a run that verified nothing must say so in words:\n%s", output)
	}
	// It must not be phrased as an alarm either. Following a catalog whose plugins you have
	// not installed is an ordinary state, and a tool that shouts about it gets ignored when
	// it shouts about something real.
	if !strings.Contains(output, "fine if you did not expect them here") {
		t.Errorf("the sentence must not read as a failure:\n%s", output)
	}
}

// The plain all-clear survives. When plugins really were verified, nothing must suggest
// otherwise — a caveat printed after a genuine success is how a reader learns to skip them.
func TestAVerifiedRunIsNotToldNothingWasVerified(t *testing.T) {
	output := capture(t, func() {
		writeReconcileReport([]marketplace.Result{
			{Outcome: marketplace.OutcomeVerified, Plugin: "delegate"},
			{Outcome: marketplace.OutcomeAbsent, Plugin: "not-here"},
		}, nil, t.TempDir(), false)
	})

	if strings.Contains(output, "Nothing was verified") {
		t.Errorf("one plugin verified is not nothing:\n%s", output)
	}
	if !strings.Contains(output, "1 verified · 1 not installed here") {
		t.Errorf("both buckets must be visible:\n%s", output)
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
