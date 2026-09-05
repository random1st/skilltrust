package notary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/report"
)

// EventReceipt records admission independently of the keys currently enabled for
// new uploads. The public key verifies history; it never grants new access.
type EventReceipt struct {
	Organisation string  `json:"organisation"`
	PublicKey    string  `json:"public_key"`
	Receipt      Receipt `json:"receipt"`
}

// EventReceiptStorage is the hosted admission evidence extension. Receipts are
// immutable: a retry preserves the first acceptance time and original signer.
type EventReceiptStorage interface {
	PutEventReceipt(org, name string, receipt EventReceipt) error
	GetEventReceipt(org, name string) (EventReceipt, error)
}

// HistoricalMachineRegistry supplies retained public keys only to verify legacy
// signatures. Their presence is not evidence of admission at the event's claimed
// time, and this interface must never be used to authorize a new upload.
type HistoricalMachineRegistry interface {
	HistoricalMachineKeys(org string) (*attest.TrustedKeys, error)
}

func eventIdentity(envelope []byte) (name, digest string) {
	sum := sha256.Sum256(envelope)
	return hex.EncodeToString(sum[:8]) + ".json", hex.EncodeToString(sum[:])
}

// AcceptVerifiedEvent applies current machine admission before persisting the
// original Event v1 envelope. The receipt is stored first so an interrupted write
// cannot expose an admitted event without the evidence of its acceptance.
func (s *Service) AcceptVerifiedEvent(org Org, body []byte, trusted *attest.TrustedKeys, now time.Time) (string, error) {
	storage, ok := s.storage.(EventReceiptStorage)
	if !ok {
		return "", fmt.Errorf("event admission evidence storage is unavailable")
	}
	if trusted == nil || trusted.Len() == 0 {
		return "", fmt.Errorf("%w: no active machine key", ErrRefused)
	}
	raw, envelope, err := parseEnvelope(body)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxEventBytes {
		return "", fmt.Errorf("%w: event is too large", ErrRefused)
	}
	_, signer, err := report.Verify(envelope, trusted)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRefused, err)
	}
	key, found := trusted.Lookup(signer)
	if !found {
		return "", fmt.Errorf("%w: no active signer", ErrRefused)
	}
	pem, err := attest.EncodePublicKey(key)
	if err != nil {
		return "", err
	}
	name, digest := eventIdentity(raw)
	receipt := EventReceipt{Organisation: org.Name, PublicKey: string(pem), Receipt: Receipt{Signer: signer, AcceptedAt: now.UTC(), Digest: digest}}
	if err := storage.PutEventReceipt(org.Name, name, receipt); err != nil {
		return "", err
	}
	if err := s.storage.PutEvent(org.Name, name, raw); err != nil {
		return "", err
	}
	return name, nil
}

// verifyAcceptedEvent distinguishes legacy envelopes without a receipt (found=false)
// from admission evidence that exists but fails verification (found=true, err!=nil).
// A corrupt receipt must not fall back to a different source of attribution.
func (s *Service) verifyAcceptedEvent(org string, raw []byte) (event *report.Event, signer string, found bool, err error) {
	storage, ok := s.storage.(EventReceiptStorage)
	if !ok {
		return nil, "", false, nil
	}
	name, digest := eventIdentity(raw)
	receipt, err := storage.GetEventReceipt(org, name)
	if errors.Is(err, ErrAbsent) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", true, err
	}
	if receipt.Organisation != org || receipt.Receipt.Digest != digest || receipt.Receipt.AcceptedAt.IsZero() {
		return nil, "", true, fmt.Errorf("event receipt does not match its envelope")
	}
	public, err := attest.ParsePublicKey([]byte(receipt.PublicKey))
	if err != nil || attest.KeyID(public) != receipt.Receipt.Signer {
		return nil, "", true, fmt.Errorf("event receipt does not match its signer")
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, "", true, err
	}
	event, signer, err = report.Verify(&envelope, attest.NewTrustedKeys(public))
	return event, signer, true, err
}

var eventReceiptName = regexp.MustCompile(`^[0-9a-f]{16}\.json$`)

// ValidateEventReceipt checks both the immutable object identity and key binding.
func ValidateEventReceipt(org, name string, receipt EventReceipt) error {
	if !ValidName(org) || !eventReceiptName.MatchString(name) || receipt.Organisation != org || receipt.Receipt.AcceptedAt.IsZero() {
		return fmt.Errorf("invalid event receipt identity")
	}
	digest, err := hex.DecodeString(receipt.Receipt.Digest)
	if err != nil || len(digest) != sha256.Size || name != hex.EncodeToString(digest[:8])+".json" {
		return fmt.Errorf("event receipt digest does not match its name")
	}
	key, err := attest.ParsePublicKey([]byte(receipt.PublicKey))
	if err != nil || attest.KeyID(key) != receipt.Receipt.Signer {
		return fmt.Errorf("invalid event receipt signer")
	}
	return nil
}

// SameEventReceipt permits a retry to retain the earlier acceptance time, while
// refusing conflicting attribution under an existing content-derived name.
func SameEventReceipt(a, b EventReceipt) bool {
	return a.Organisation == b.Organisation && a.Receipt.Digest == b.Receipt.Digest &&
		a.Receipt.Signer == b.Receipt.Signer && a.PublicKey == b.PublicKey
}

func (f *FileStorage) PutEventReceipt(org, name string, receipt EventReceipt) error {
	if err := ValidateEventReceipt(org, name, receipt); err != nil {
		return err
	}
	directory := filepath.Join(f.root, "receipts", org)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	staged, err := os.CreateTemp(directory, ".receipt-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if _, err := staged.Write(body); err != nil {
		staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	// Link publishes a complete file only if the destination does not exist.
	if err := os.Link(staged.Name(), filepath.Join(directory, name)); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := f.GetEventReceipt(org, name)
		if readErr != nil {
			return readErr
		}
		if !SameEventReceipt(existing, receipt) {
			return fmt.Errorf("%w: conflicting event receipt", ErrRefused)
		}
	}
	return nil
}

func (f *FileStorage) GetEventReceipt(org, name string) (EventReceipt, error) {
	if !ValidName(org) || !eventReceiptName.MatchString(name) {
		return EventReceipt{}, fmt.Errorf("invalid event receipt identity")
	}
	body, err := os.ReadFile(filepath.Join(f.root, "receipts", org, name))
	if errors.Is(err, os.ErrNotExist) {
		return EventReceipt{}, ErrAbsent
	}
	if err != nil {
		return EventReceipt{}, err
	}
	var receipt EventReceipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return EventReceipt{}, err
	}
	return receipt, ValidateEventReceipt(org, name, receipt)
}
