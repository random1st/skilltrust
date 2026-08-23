package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
)

func TestAnEventRoundTripsAndCarriesItsSeverity(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{
		Kind: KindRevoked, At: time.Now().UTC(), Machine: "laptop-1",
		Marketplace: "acme", Plugin: "deploy-runbook",
	}, private)
	if err != nil {
		t.Fatal(err)
	}

	event, _, err := Verify(envelope, attest.NewTrustedKeys(public))
	if err != nil {
		t.Fatal(err)
	}
	if event.Severity != "high" {
		t.Fatalf("severity = %q; a receiver routes on this field", event.Severity)
	}
	if event.Summary() == "" {
		t.Fatal("an alert needs a line a human reads first")
	}
}

// An aggregate built from rows nobody signed looks like evidence and is not. Any machine
// could otherwise file a report as any other.
func TestAnEventFromAnUnknownMachineIsRefused(t *testing.T) {
	_, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	stranger, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{Kind: KindRestored, At: time.Now().UTC()}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(envelope, attest.NewTrustedKeys(stranger)); err == nil {
		t.Fatal("an event signed by a machine outside the trusted set must be refused")
	}
}

// A signature over an event must not be replayable as an attestation about a skill, which is
// what binding the payload type into the signed bytes is for.
func TestAnEventSignatureIsNotAnAttestation(t *testing.T) {
	public, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(Event{Kind: KindRestored, At: time.Now().UTC()}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := attest.Verify(envelope, attest.NewTrustedKeys(public)); err == nil {
		t.Fatal("an event envelope must not verify as an attestation")
	}
}

// The one incident worth hearing about is disproportionately likely to be the one that
// happened while the network was unreachable, so events accumulate rather than vanish.
func TestTheSpoolKeepsEventsInOrderAndNeverOverwrites(t *testing.T) {
	_, private, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	spool := Spool{Directory: filepath.Join(t.TempDir(), "events")}
	at := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)

	var written []string
	for range 3 {
		envelope, err := Sign(Event{Kind: KindRestored, At: at}, private)
		if err != nil {
			t.Fatal(err)
		}
		// The same instant for all three, which is what makes the names collide.
		path, err := spool.Add(envelope, at, "restored")
		if err != nil {
			t.Fatal(err)
		}
		written = append(written, path)
	}

	seen := map[string]struct{}{}
	for _, path := range written {
		if _, repeat := seen[path]; repeat {
			t.Fatalf("%s was written twice; an event overwrote another", path)
		}
		seen[path] = struct{}{}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("spooled event missing: %v", err)
		}
	}

	pending, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 3 {
		t.Fatalf("pending = %d, want 3", len(pending))
	}
	for index := 1; index < len(pending); index++ {
		if pending[index-1] >= pending[index] {
			t.Fatal("a receiver should see events oldest first")
		}
	}
}

// A machine with nowhere to report is a legitimate configuration: the spool is still
// readable, and an administrator can collect it. It must not be an error.
func TestNoDestinationsIsNotAFailure(t *testing.T) {
	if err := Deliver(&Config{}, Event{Kind: KindRestored}, nil, time.Second); err != nil {
		t.Fatalf("spool-only reporting must be allowed: %v", err)
	}
}
