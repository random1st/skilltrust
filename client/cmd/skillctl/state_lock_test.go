package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func TestConsumerStateCLIProcess(t *testing.T) {
	if os.Getenv("AXELA_STATE_CLI_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = os.Args[i+1:]
			fmt.Println("ready")
			main()
		}
	}
	t.Fatal("child arguments missing")
}

func TestConsumerStateLockCoordinatesRealCLITrustWrites(t *testing.T) {
	f := newPublicSubscriptionFixture(t)
	if _, _, err := f.r.subscribe(context.Background(), "axela://team/acme"); err != nil {
		t.Fatal(err)
	}
	pins, err := attest.PinnedKeys(defaultTrustedKeys())
	if err != nil {
		t.Fatal(err)
	}
	var label string
	for candidate := range pins {
		if strings.HasPrefix(candidate, "notary:") {
			label = candidate
			break
		}
	}
	if label == "" {
		t.Fatal("fixture has no notary pin")
	}
	unlock, err := acquireConsumerState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, self, "-test.run=^TestConsumerStateCLIProcess$", "--", "axela", "trust", "--remove", label)
	child.Env = append(os.Environ(), "AXELA_STATE_CLI_TEST=1")
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("CLI child did not start: %q %v", line, err)
	}
	finished := make(chan error, 1)
	go func() { finished <- child.Wait() }()
	select {
	case err := <-finished:
		t.Fatalf("CLI bypassed an in-progress state transaction: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	current, err := attest.PinnedKeys(defaultTrustedKeys())
	if err != nil || current[label] == nil {
		t.Fatal("a real CLI writer changed pins inside another transaction")
	}
	unlock()
	unlock = nil
	if err := <-finished; err != nil {
		t.Fatalf("CLI failed after the transaction released its lock: %v", err)
	}
	current, err = attest.PinnedKeys(defaultTrustedKeys())
	if err != nil || current[label] != nil {
		t.Fatal("explicit trust removal was not applied after releasing the transaction")
	}
}
