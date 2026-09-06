package main

import (
	"context"
	"os"
	"testing"
)

func TestPreSkillStateLockFailureUsesTheNativeBlockingExit(t *testing.T) {
	t.Setenv("SKILLTRUST_HOME", t.TempDir())
	unlock, err := acquireConsumerState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	os.Args = []string{"axela", "hook", "pre-skill", "--claude-json"}
	if code := runCLI(); code != exitDeny {
		t.Fatalf("native hook must block when another transaction prevents checking: got %d want %d", code, exitDeny)
	}
}
