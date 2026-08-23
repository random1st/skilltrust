// Package report records what a machine did and hands it to whoever should hear about it.
//
// Reporting is an output and never an input. The verifier stays a pure offline function over
// the bytes on disk, the signed catalog and the pinned keys; if the network is gone, a
// tampered plugin is still detected and still put back, and only the telling is delayed. A
// design where the check needs a server to reach a verdict is a design that fails open the
// first time the server is unreachable, which is exactly when it matters.
//
// Events are signed by the machine's own key. Without that, any machine could file a report
// as any other, and a console aggregating them would be reporting fiction with a hostname
// attached.
package report

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/client/internal/attest"
)

// PayloadType keeps an event signature from being replayed as an attestation or a catalog.
const PayloadType = "application/vnd.skilltrust.event.v1+json"

// EventVersion is the payload schema version.
const EventVersion = 1

// Kind is what happened. Only things worth waking someone for are kinds; an unchanged plugin
// produces no event at all, because a stream that reports normality is a stream nobody reads.
type Kind string

const (
	// KindRestored means a signed plugin had been changed on this machine and was put back.
	KindRestored Kind = "restored"
	// KindRevoked means a revoked plugin was found installed.
	KindRevoked Kind = "revoked"
	// KindUnverifiable means a signed plugin could not be checked or could not be repaired.
	KindUnverifiable Kind = "unverifiable"
	// KindCatalogUnusable means a marketplace could not be verified, so its plugins went
	// unchecked. Silence about that would be indistinguishable from everything being fine.
	KindCatalogUnusable Kind = "catalog-unusable"
)

// Severity lets a receiver route without parsing the whole event.
func (k Kind) Severity() string {
	switch k {
	case KindRevoked:
		return "high"
	case KindRestored, KindUnverifiable:
		return "medium"
	default:
		return "low"
	}
}

// Event is one thing that happened on one machine.
type Event struct {
	Version     int       `json:"version"`
	Kind        Kind      `json:"kind"`
	Severity    string    `json:"severity"`
	At          time.Time `json:"at"`
	Machine     string    `json:"machine"`
	Host        string    `json:"host,omitempty"`
	Marketplace string    `json:"marketplace,omitempty"`
	Plugin      string    `json:"plugin,omitempty"`
	PluginVer   string    `json:"plugin_version,omitempty"`
	Sequence    int64     `json:"catalog_sequence,omitempty"`
	Signed      string    `json:"signed_digest,omitempty"`
	Found       string    `json:"found_digest,omitempty"`
	Quarantine  string    `json:"quarantine,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

// Summary is the one line a human reads first, in an alert or a console row.
func (e Event) Summary() string {
	switch e.Kind {
	case KindRestored:
		return fmt.Sprintf("%s was changed on %s and put back to what %s publishes",
			e.Plugin, e.displayHost(), e.Marketplace)
	case KindRevoked:
		return fmt.Sprintf("%s is revoked by %s but was installed on %s",
			e.Plugin, e.Marketplace, e.displayHost())
	case KindUnverifiable:
		return fmt.Sprintf("%s on %s could not be verified: %s",
			e.Plugin, e.displayHost(), e.Detail)
	case KindCatalogUnusable:
		if e.Marketplace == "" {
			return fmt.Sprintf("a signed marketplace could not be used on %s, so its "+
				"plugins were not checked: %s", e.displayHost(), e.Detail)
		}
		return fmt.Sprintf("%s could not be used on %s, so its plugins were not checked: %s",
			e.Marketplace, e.displayHost(), e.Detail)
	}
	return string(e.Kind)
}

func (e Event) displayHost() string {
	if e.Host != "" {
		return e.Host
	}
	return e.Machine
}

// Complete fills the fields derived from the kind, so the event that is signed and the event
// that is delivered are the same one. They were briefly not: Sign filled them on its own copy
// and every notification went out with an empty severity, which is the field a receiver
// routes on.
func (e *Event) Complete() {
	e.Version = EventVersion
	e.Severity = e.Kind.Severity()
}

// Sign wraps an event in a DSSE envelope under the machine's key.
func Sign(event Event, key ed25519.PrivateKey) (*attest.Envelope, error) {
	event.Complete()
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return attest.SignPayload(PayloadType, payload, key), nil
}

// Verify checks an event against a set of machine keys and returns it with the signer.
func Verify(envelope *attest.Envelope, trusted *attest.TrustedKeys) (*Event, string, error) {
	payload, keyID, err := attest.VerifyPayload(envelope, PayloadType, trusted)
	if err != nil {
		return nil, "", err
	}
	var event Event
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, "", fmt.Errorf("event payload is not readable: %w", err)
	}
	if event.Version != EventVersion {
		return nil, "", fmt.Errorf("event version %d is not understood by this build",
			event.Version)
	}
	return &event, keyID, nil
}

// Spool is a directory of events waiting to be delivered.
//
// Events are written before delivery is attempted and removed only once one succeeds. A
// machine that is offline, or whose receiver is down, accumulates rather than loses: the
// alternative is that the one incident worth hearing about is the one that happened while
// the VPN was down.
type Spool struct{ Directory string }

// Add writes an event to the spool.
func (s Spool) Add(envelope *attest.Envelope, at time.Time, name string) (string, error) {
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return "", err
	}
	base := filepath.Join(s.Directory,
		fmt.Sprintf("%s-%s", at.UTC().Format("20060102T150405Z"), name))
	path := base + ".json"
	for attempt := 1; ; attempt++ {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			break
		}
		if attempt > 1000 {
			return "", fmt.Errorf("cannot find an unused event name beside %s", base)
		}
		path = fmt.Sprintf("%s-%d.json", base, attempt)
	}
	return path, envelope.Save(path)
}

// Pending lists spooled events oldest first, which is the order a receiver should see them.
func (s Spool) Pending() ([]string, error) {
	entries, err := os.ReadDir(s.Directory)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			paths = append(paths, filepath.Join(s.Directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}
