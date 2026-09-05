package notary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

// MaxEventBytes bounds one submitted event. An event is a sentence about one incident;
// a megabyte of it is something else wearing the endpoint.
const MaxEventBytes = 1 << 20

// MaxCheckBytes bounds one submitted current check. A current-state row is summary data,
// not a log blob, and it is stored beside a decoded copy and receipt in hosted state.
const MaxCheckBytes = 32 << 10

const maxCheckFreshnessWindow = 30 * 24 * time.Hour

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
	envelope, parsed, err := parseEnvelope(body)
	if err != nil {
		return "", err
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

// AcceptCheck verifies, receipts and stores one machine's current-state report.
func (s *Service) AcceptCheck(
	org Org, body []byte, trusted *attest.TrustedKeys, now time.Time,
) (Receipt, error) {
	if trusted == nil || trusted.Len() == 0 {
		return Receipt{}, fmt.Errorf("%w: no machine keys are registered for current checks", ErrRefused)
	}
	envelope, parsed, err := parseEnvelope(body)
	if err != nil {
		return Receipt{}, err
	}
	if len(envelope) > MaxCheckBytes {
		return Receipt{}, fmt.Errorf("%w: the check is too large", ErrRefused)
	}
	if parsed.PayloadType != report.CheckPayloadType {
		return Receipt{}, fmt.Errorf("%w: payload type %q is not a current check",
			ErrRefused, parsed.PayloadType)
	}
	check, signer, err := report.VerifyCheck(parsed, trusted)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if check.CheckedAt.After(now.Add(5 * time.Minute)) {
		return Receipt{}, fmt.Errorf("%w: checked_at is in the future", ErrRefused)
	}
	if !check.FreshUntil.IsZero() {
		if !check.FreshUntil.After(check.CheckedAt) {
			return Receipt{}, fmt.Errorf("%w: fresh_until must be after checked_at", ErrRefused)
		}
		if check.FreshUntil.After(check.CheckedAt.Add(maxCheckFreshnessWindow)) {
			return Receipt{}, fmt.Errorf("%w: fresh_until is too far after checked_at", ErrRefused)
		}
	}
	for _, catalogCheck := range check.Catalogs {
		if !catalogCheck.ValidUntil.IsZero() && !check.FreshUntil.IsZero() &&
			check.FreshUntil.After(catalogCheck.ValidUntil) {
			return Receipt{}, fmt.Errorf("%w: fresh_until exceeds %s catalog validity",
				ErrRefused, catalogCheck.Name)
		}
	}
	sum := sha256.Sum256(envelope)
	receipt := Receipt{
		Signer:     signer,
		AcceptedAt: now.UTC(),
		Digest:     hex.EncodeToString(sum[:]),
	}
	return s.storage.SaveCheck(org.Name, CheckRecord{
		Result:   *check,
		Receipt:  receipt,
		Envelope: append(json.RawMessage(nil), envelope...),
	})
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

// ServeChecks returns the stored current-state rows for one organisation.
func (s *Service) ServeChecks(org Org) ([]CheckRecord, error) {
	return s.storage.ListChecks(org.Name)
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

func parseEnvelope(body []byte) (json.RawMessage, *attest.Envelope, error) {
	envelope := extractEnvelope(body)
	if envelope == nil {
		return nil, nil, fmt.Errorf("%w: neither a signed envelope nor a notification carrying one", ErrRefused)
	}
	var parsed attest.Envelope
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return nil, nil, fmt.Errorf("%w: the envelope is not readable: %v", ErrRefused, err)
	}
	return envelope, &parsed, nil
}
