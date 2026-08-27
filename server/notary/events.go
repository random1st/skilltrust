package notary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/random1st/skilltrust/internal/attest"
	"github.com/random1st/skilltrust/internal/report"
)

// MaxEventBytes bounds one submitted event. An event is a sentence about one incident;
// a megabyte of it is something else wearing the endpoint.
const MaxEventBytes = 1 << 20

// notification is the body a machine's webhook destination already sends. Only the
// envelope is kept: everything else in it is unsigned convenience for chat receivers,
// and storing unsigned prose beside signed evidence invites reading the wrong one.
type notification struct {
	Envelope json.RawMessage `json:"envelope"`
}

// AcceptEvent stores a machine's signed event and reports the name it was stored under.
//
// The notary does not verify machine signatures — it has no registry of machine keys,
// and inventing one here would make the mailbox the trust root. It checks shape (a DSSE
// envelope of the event payload type) and keeps the envelope byte-for-byte; `skillctl
// fleet` verifies against the keys the administrator actually trusts, and refuses what
// they did not sign. Reporting stays an output: nothing a machine does depends on this.
func (s *Service) AcceptEvent(org Org, body []byte) (string, error) {
	envelope := extractEnvelope(body)
	if envelope == nil {
		return "", fmt.Errorf("%w: neither a signed envelope nor a notification carrying one", ErrRefused)
	}

	var parsed attest.Envelope
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return "", fmt.Errorf("%w: the envelope is not readable: %v", ErrRefused, err)
	}
	if parsed.PayloadType != report.PayloadType {
		return "", fmt.Errorf("%w: payload type %q is not an event", ErrRefused, parsed.PayloadType)
	}
	if len(parsed.Signatures) == 0 {
		return "", fmt.Errorf("%w: an unsigned event would be refused by every reader; not storing it", ErrRefused)
	}

	// Content-addressed naming makes redelivery idempotent: a spool that retries after a
	// partial failure stores the same record, not a duplicate row in somebody's count.
	sum := sha256.Sum256(envelope)
	name := hex.EncodeToString(sum[:8]) + ".json"
	if err := s.storage.PutEvent(org.Name, name, envelope); err != nil {
		return "", err
	}
	return name, nil
}

// ServeEvents returns every stored envelope, oldest name first.
func (s *Service) ServeEvents(org Org) ([]json.RawMessage, error) {
	stored, err := s.storage.ListEvents(org.Name)
	if err != nil {
		return nil, err
	}
	events := make([]json.RawMessage, 0, len(stored))
	for _, body := range stored {
		events = append(events, json.RawMessage(body))
	}
	return events, nil
}

// extractEnvelope accepts either a bare DSSE envelope or the notification wrapper the
// client's webhook destination sends, so pointing an existing reporting.json at the
// notary needs no client change.
func extractEnvelope(body []byte) json.RawMessage {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil
	}
	if _, isEnvelope := probe["payloadType"]; isEnvelope {
		return body
	}
	var wrapped notification
	if err := json.Unmarshal(body, &wrapped); err != nil || len(wrapped.Envelope) == 0 {
		return nil
	}
	return wrapped.Envelope
}
