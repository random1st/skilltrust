package main

import (
	"os"
	"testing"
)

func TestConnectionAndReportHelpSucceedsWithoutCreatingConfiguration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SKILLTRUST_HOME", home)
	for _, help := range []string{"-h", "--help"} {
		if code := runConnect([]string{help}); code != exitClean {
			t.Fatalf("connect %s = %d, want success", help, code)
		}
		if code := runReport([]string{"flush", help}); code != exitClean {
			t.Fatalf("report flush %s = %d, want success", help, code)
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("help modified local configuration: entries=%v err=%v", entries, err)
	}
}

func TestReportFlushBoundsItsWaitBeforeAccessingConfiguration(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	for _, args := range [][]string{nil, {"unknown"}, {"flush", "-timeout", "0s"}, {"flush", "-timeout", "2m"}, {"flush", "/a/path"}} {
		if code := runReport(args); code != exitUsage {
			t.Fatalf("report %v = %d, want invalid usage", args, code)
		}
	}
	if code := runReport([]string{"flush"}); code != exitClean {
		t.Fatalf("empty spool flush = %d, want success", code)
	}
}
