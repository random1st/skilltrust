package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

func TestDemoEvidenceSelectsTheSignedRestoreRegardlessOfFilenameOrder(t *testing.T) {
	home := t.TempDir()
	public, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WritePublicKey(filepath.Join(home, "signer.pub"), public); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "events")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, one := range []struct {
		file string
		kind report.Kind
	}{
		{"001-detection.json", report.KindUnverifiable},
		{"002-restoration.json", report.KindRestored},
	} {
		envelope, err := report.Sign(report.Event{
			Kind: one.kind, At: time.Now().UTC(), Machine: "demo", Plugin: "runbook",
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := envelope.Save(filepath.Join(root, one.file)); err != nil {
			t.Fatal(err)
		}
	}
	output := capture(t, func() {
		if code := showDemoEvidence(home); code != exitClean {
			t.Fatalf("evidence exited %d", code)
		}
	})
	if !strings.Contains(output, "kind           restored") || strings.Contains(output, "001-detection") {
		t.Fatalf("wrong evidence shown: %s", output)
	}
}

// The demo is the first thing a stranger runs and the only claim most of them will ever
// check, so a break in it is a break in the pitch. It runs here for the same reason the
// action runs against this repository: a demo nobody executes is a screenshot.
//
// This asserts the story happened, not that the output reads a particular way. Pinning the
// prose would make every wording change a failing test, which is how a test that guards
// something real gets deleted for being annoying.
func TestTheDemoTellsTheWholeStory(t *testing.T) {
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		if _, err := os.Stat("/usr/local/bin/git"); err != nil {
			t.Skip("no git here, and the demo publishes from a repository")
		}
	}
	sandbox := filepath.Join(t.TempDir(), "demo")

	output := capture(t, func() {
		if code := runDemo([]string{"--dir", sandbox, "--keep"}); code != exitClean {
			t.Errorf("demo exited %d", code)
		}
	})

	// The five beats the demo exists to show, in the order that makes them mean anything.
	for _, beat := range []string{
		"signed      1 of 1 plugin", // published and signed
		"pinned keys",               // followed, with the publisher's key pinned
		"changed",                   // detected
		"restored",                  // put back
		"kind           restored",   // and filed as a signed event
	} {
		if !strings.Contains(output, beat) {
			t.Errorf("the demo never got to %q:\n%s", beat, output)
		}
	}
	if strings.Index(output, "changed") > strings.Index(output, "kind           restored") {
		t.Error("the demo reports the restore before the detection")
	}

	// The claim the demo makes about itself: the installed file is the published one again.
	installed := filepath.Join(sandbox, "client-home", "plugins", "cache", "acme",
		"deploy-runbook", "1.0.0", "SKILL.md")
	body, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != demoSkill {
		t.Errorf("the installed file is not the published one:\n%s", body)
	}
	// And the copy that was there is kept rather than destroyed, which is what makes the
	// restore reversible.
	quarantine, err := os.ReadDir(filepath.Join(sandbox, "skilltrust-home", "quarantine"))
	if err != nil || len(quarantine) == 0 {
		t.Error("the changed copy was not kept in quarantine")
	}
}

// The promise on the tin: a stranger can run this before they trust the tool. That is only
// true if it cannot reach their real home — the one place it could, since every command it
// calls resolves keys and pins through SKILLTRUST_HOME.
func TestTheDemoLeavesTheRealHomeAlone(t *testing.T) {
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("no git here, and the demo publishes from a repository")
	}
	real := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", real)
	sandbox := filepath.Join(t.TempDir(), "demo")

	capture(t, func() { runDemo([]string{"--dir", sandbox}) })

	entries, err := os.ReadDir(real)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the demo wrote into the machine's own home: %v", entries)
	}
	// And it must put the variable back, or every command after it in the same process
	// would quietly address the sandbox.
	if os.Getenv("SKILLTRUST_HOME") != real {
		t.Errorf("SKILLTRUST_HOME was left as %q", os.Getenv("SKILLTRUST_HOME"))
	}
}

// Without --keep the sandbox goes away. A tool that leaves a directory behind every time it
// is demonstrated is one people stop demonstrating.
func TestTheDemoCleansUpAfterItself(t *testing.T) {
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("no git here, and the demo publishes from a repository")
	}
	var sandbox string
	output := capture(t, func() { runDemo(nil) })
	for _, line := range strings.Split(output, "\n") {
		if after, found := strings.CutPrefix(strings.TrimSpace(line), "sandbox"); found {
			sandbox = strings.TrimSpace(after)
			break
		}
	}
	if sandbox == "" {
		t.Fatalf("the demo did not say where its sandbox was:\n%s", output)
	}
	if _, err := os.Stat(sandbox); !os.IsNotExist(err) {
		t.Errorf("%s outlived the demo", sandbox)
	}
}
