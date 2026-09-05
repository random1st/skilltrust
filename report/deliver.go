package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
)

// ErrNoDestinations means nobody is configured to hear about events. It is an error, not a
// success: a caller that deletes its spooled copy on a nil return would otherwise write
// every event and immediately destroy it, leaving a default install that reports nowhere —
// not to a console, not to a directory, not even to its own disk.
var ErrNoDestinations = errors.New("no reporting destinations configured")

// Destination is where events go. Several may be configured; each is tried independently, and
// an event is kept in the spool until at least one accepts it.
type Destination struct {
	// Kind is "webhook", "command" or "file".
	Kind string `json:"kind"`
	// URL is the endpoint for a webhook.
	URL string `json:"url,omitempty"`
	// Headers are sent with a webhook request, for an API token or a routing key.
	Headers map[string]string `json:"headers,omitempty"`
	// Command receives the event as JSON on standard input. This is the escape hatch that
	// makes every other transport somebody already runs — syslog, a queue, an MDM channel —
	// reachable without this project growing an integration for each.
	Command []string `json:"command,omitempty"`
	// Directory receives a copy of the signed envelope, for a share or a synced folder.
	Directory string `json:"directory,omitempty"`
	// Payloads is the set of report types this destination accepts: "events" and/or "checks".
	// Empty keeps backward compatibility and means "events only".
	Payloads []string `json:"payloads,omitempty"`
	// HealthyChecks opts a destination into routine healthy current-state reports. Without it
	// a destination still receives checks that need attention, but not the quiet all-clear.
	HealthyChecks bool `json:"healthy_checks,omitempty"`
	// BearerTokenFile points at an owner-only file whose trimmed contents become the webhook
	// Authorization header.
	BearerTokenFile string `json:"bearer_token_file,omitempty"`
	// ReceiptFile records that this webhook accepted a payload, so a caller can distinguish
	// "the cloud received it" from "we tried".
	ReceiptFile string `json:"receipt_file,omitempty"`
}

// Config is how a machine is told where to report. It sits beside the policy so the same
// configuration management places both.
type Config struct {
	// Machine names this machine in reports. Defaults to the hostname.
	Machine string `json:"machine,omitempty"`
	// Destinations is where events go. Empty means events are spooled and never sent, which
	// is a legitimate configuration: the spool is still readable, and `skillctl fleet` can
	// aggregate collected spools.
	Destinations []Destination `json:"destinations,omitempty"`
	// Timeout bounds one delivery attempt.
	Timeout time.Duration `json:"-"`
	// TimeoutSeconds is the serialized form of Timeout.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// LoadConfig reads reporting configuration, treating absence as "spool only".
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("%s is not a readable reporting configuration: %w", path, err)
	}
	if config.TimeoutSeconds > 0 {
		config.Timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}
	return &config, nil
}

// Notification is the human-readable body a webhook receives.
//
// It carries the whole event as well as a summary line, so a receiver can be a Slack webhook
// that only reads `text` or a SIEM that reads every field, without this project shipping an
// integration for either.
type Notification struct {
	Text     string `json:"text"`
	Severity string `json:"severity"`
	Event    Event  `json:"event"`
	Envelope any    `json:"envelope,omitempty"`
}

// CheckNotification is the body a current-check destination receives.
type CheckNotification struct {
	Text     string      `json:"text"`
	Status   string      `json:"status"`
	Healthy  bool        `json:"healthy"`
	Result   CheckResult `json:"result"`
	Envelope any         `json:"envelope,omitempty"`
}

type deliveryPayload string

const (
	payloadEvents deliveryPayload = "events"
	payloadChecks deliveryPayload = "checks"
)

type deliveryItem struct {
	payload  deliveryPayload
	when     time.Time
	machine  string
	summary  string
	severity string
	healthy  bool
	event    *Event
	check    *CheckResult
	envelope []byte
}

type deliveryState struct {
	Version int             `json:"version"`
	Digest  string          `json:"digest,omitempty"`
	Acked   map[string]bool `json:"acked,omitempty"`
}

type receiptState struct {
	Version     int    `json:"version"`
	AcceptedURL string `json:"accepted_url,omitempty"`
	AcceptedAt  string `json:"accepted_at,omitempty"`
	Signer      string `json:"signer,omitempty"`
	Digest      string `json:"digest,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type webhookReceipt struct {
	Receipt struct {
		Signer     string    `json:"signer"`
		AcceptedAt time.Time `json:"accepted_at"`
		Digest     string    `json:"digest"`
	} `json:"receipt"`
}

// Deliver sends one spooled event to every configured destination and reports whether all
// eligible destinations accepted it.
//
// Best-effort by design: a failed delivery leaves the event in the spool for the next run
// rather than blocking anything. A machine that cannot reach its receiver has still detected
// and repaired the problem, and the only thing outstanding is telling somebody.
func Deliver(config *Config, event Event, envelopeBytes []byte, timeout time.Duration) error {
	return deliver("", config, deliveryItem{
		payload: payloadEvents, when: event.At, machine: event.Machine,
		summary: event.Summary(), severity: event.Severity, event: &event, envelope: envelopeBytes,
	}, timeout)
}

func deliverOne(
	destination Destination, item deliveryItem, timeout time.Duration,
) error {
	switch destination.Kind {
	case "webhook":
		body, err := webhookBody(item)
		if err != nil {
			return err
		}
		return postWebhook(destination, item, body, timeout)
	case "command":
		body, err := notificationBody(item)
		if err != nil {
			return err
		}
		return runCommand(destination, body, timeout)
	case "file":
		return writeFile(destination, item)
	default:
		return fmt.Errorf("unknown destination kind %q", destination.Kind)
	}
}

// DeliverQueuedEvent sends one spooled event and remembers which destinations already
// accepted it, so a retry does not duplicate the destinations that already succeeded.
func DeliverQueuedEvent(
	path string, config *Config, event Event, envelopeBytes []byte, timeout time.Duration,
) error {
	return deliver(path, config, deliveryItem{
		payload: payloadEvents, when: event.At, machine: event.Machine,
		summary: event.Summary(), severity: event.Severity, event: &event, envelope: envelopeBytes,
	}, timeout)
}

// DeliverQueuedCheck sends one spooled current-check result and remembers which
// destinations already accepted it.
func DeliverQueuedCheck(
	path string, config *Config, check CheckResult, envelopeBytes []byte, timeout time.Duration,
) error {
	return deliver(path, config, deliveryItem{
		payload: payloadChecks, when: check.CheckedAt, machine: check.Machine,
		summary: check.Summary(), healthy: check.Healthy(), check: &check, envelope: envelopeBytes,
	}, timeout)
}

func deliver(path string, config *Config, item deliveryItem, timeout time.Duration) error {
	if len(config.Destinations) == 0 {
		return ErrNoDestinations
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)

	state, err := loadState(path)
	if err != nil {
		return err
	}
	state.bind(item.envelope)

	var supported []Destination
	for _, destination := range config.Destinations {
		if accepts(destination, item) {
			supported = append(supported, destination)
		}
	}
	if len(supported) == 0 {
		return ErrNoDestinations
	}

	var failures []string
	for _, destination := range supported {
		id, err := destinationID(destination)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", destination.Kind, err))
			continue
		}
		if state.Acked[id] {
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			failures = append(failures, fmt.Sprintf("%s: delivery timed out", destination.Kind))
			continue
		}
		if err := deliverOne(destination, item, remaining); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", destination.Kind, err))
			continue
		}
		state.Acked[id] = true
		if err := saveState(path, state); err != nil {
			return err
		}
	}

	for _, destination := range supported {
		id, err := destinationID(destination)
		if err != nil || !state.Acked[id] {
			if len(failures) == 0 {
				failures = append(failures, "delivery is still pending")
			}
			return fmt.Errorf("not every destination has accepted this %s yet: %s",
				item.payload, strings.Join(failures, "; "))
		}
	}
	if path != "" {
		_ = os.Remove(ackPath(path))
	}
	return nil
}

func notificationBody(item deliveryItem) ([]byte, error) {
	switch item.payload {
	case payloadChecks:
		status := "needs-attention"
		if item.healthy {
			status = "checked"
		}
		return json.Marshal(CheckNotification{
			Text: item.summary, Status: status, Healthy: item.healthy,
			Result: *item.check, Envelope: json.RawMessage(item.envelope),
		})
	default:
		return json.Marshal(Notification{
			Text: item.summary, Severity: item.severity, Event: *item.event,
			Envelope: json.RawMessage(item.envelope),
		})
	}
}

func webhookBody(item deliveryItem) ([]byte, error) {
	if item.payload == payloadChecks {
		return item.envelope, nil
	}
	return notificationBody(item)
}

func postWebhook(destination Destination, item deliveryItem, body []byte, timeout time.Duration) error {
	if destination.URL == "" {
		return fmt.Errorf("no url")
	}
	target, err := url.Parse(destination.URL)
	if err != nil {
		return err
	}
	if destination.BearerTokenFile != "" {
		if hasAuthorizationHeader(destination.Headers) {
			return fmt.Errorf("authorization is configured both as a header and as a bearer_token_file")
		}
	}
	if (destination.BearerTokenFile != "" || hasAuthorizationHeader(destination.Headers)) &&
		!secureWebhookTarget(target) {
		return fmt.Errorf("%s must use https unless it points at loopback", destination.URL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, destination.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range destination.Headers {
		request.Header.Set(name, value)
	}
	if destination.BearerTokenFile != "" {
		token, err := readBearerToken(destination.BearerTokenFile)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("%s replied %s", destination.URL, response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return err
	}
	var receipt *webhookReceipt
	if item.payload == payloadChecks {
		receipt, err = verifyWebhookReceipt(raw, item.envelope)
		if err != nil {
			return err
		}
	}
	if destination.ReceiptFile != "" {
		acceptedAt := time.Now().UTC()
		if receipt != nil {
			acceptedAt = receipt.Receipt.AcceptedAt
		}
		if err := writeReceiptFile(destination.ReceiptFile, destination.URL, acceptedAt, receipt); err != nil {
			return err
		}
	}
	return nil
}

func runCommand(destination Destination, body []byte, timeout time.Duration) error {
	if len(destination.Command) == 0 {
		return fmt.Errorf("no command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := exec.CommandContext(ctx,
		destination.Command[0], destination.Command[1:]...)
	command.WaitDelay = min(timeout, 250*time.Millisecond)
	command.Stdin = bytes.NewReader(body)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeFile(destination Destination, item deliveryItem) error {
	if destination.Directory == "" {
		return fmt.Errorf("no directory")
	}
	if err := os.MkdirAll(destination.Directory, 0o700); err != nil {
		return err
	}
	sum := sha256.Sum256(item.envelope)
	name := fmt.Sprintf("%s-%s-%s-%s.json",
		item.when.UTC().Format("20060102T150405Z"),
		sanitize(item.machine), item.payload, hex.EncodeToString(sum[:8]))
	return os.WriteFile(filepath.Join(destination.Directory, name), item.envelope, 0o600)
}

// sanitize keeps a machine name usable as a filename without deciding what a machine may be
// called.
func sanitize(name string) string {
	if name == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, name)
}

func accepts(destination Destination, item deliveryItem) bool {
	payloads := destination.Payloads
	if len(payloads) == 0 {
		return item.payload == payloadEvents
	}
	allowed := false
	for _, payload := range payloads {
		if payload == string(item.payload) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	if item.payload == payloadChecks && item.healthy && !destination.HealthyChecks {
		return false
	}
	return true
}

func destinationID(destination Destination) (string, error) {
	body, err := json.Marshal(destination)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func ackPath(path string) string { return path + ".acks.json" }

func loadState(path string) (*deliveryState, error) {
	state := &deliveryState{Version: 2, Acked: map[string]bool{}}
	if path == "" {
		return state, nil
	}
	raw, err := os.ReadFile(ackPath(path))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("%s is not a readable delivery state: %w", ackPath(path), err)
	}
	if state.Acked == nil {
		state.Acked = map[string]bool{}
	}
	return state, nil
}

func (state *deliveryState) bind(envelope []byte) {
	if state.Acked == nil {
		state.Acked = map[string]bool{}
	}
	digest := deliveryDigest(envelope)
	if state.Digest == digest {
		return
	}
	state.Version = 2
	state.Digest = digest
	state.Acked = map[string]bool{}
}

func saveState(path string, state *deliveryState) error {
	if path == "" {
		return nil
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeSidecarAtomically(ackPath(path), body)
}

func readBearerToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must be readable only by its owner", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return token, nil
}

func verifyWebhookReceipt(body, envelope []byte) (*webhookReceipt, error) {
	var payload webhookReceipt
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("webhook replied without a readable receipt: %w", err)
	}
	if payload.Receipt.Signer == "" || payload.Receipt.Digest == "" || payload.Receipt.AcceptedAt.IsZero() {
		return nil, fmt.Errorf("webhook receipt is incomplete")
	}
	var parsed attest.Envelope
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return nil, fmt.Errorf("current check envelope is not readable: %w", err)
	}
	signedByMachine := false
	for _, signature := range parsed.Signatures {
		if signature.KeyID == payload.Receipt.Signer {
			signedByMachine = true
			break
		}
	}
	if !signedByMachine {
		return nil, fmt.Errorf("webhook receipt signer %q did not sign this current check", payload.Receipt.Signer)
	}
	if payload.Receipt.Digest != deliveryDigest(envelope) {
		return nil, fmt.Errorf("webhook receipt digest does not match this current check")
	}
	return &payload, nil
}

func deliveryDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func writeReceiptFile(path, acceptedURL string, acceptedAt time.Time, receipt *webhookReceipt) error {
	state := receiptState{
		Version:     1,
		AcceptedURL: acceptedURL,
		AcceptedAt:  acceptedAt.UTC().Format(time.RFC3339),
	}
	if receipt != nil {
		state.Signer = receipt.Receipt.Signer
		state.Digest = receipt.Receipt.Digest
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeSidecarAtomically(path, append(body, '\n'))
}

func hasAuthorizationHeader(headers map[string]string) bool {
	for name := range headers {
		if strings.EqualFold(name, "Authorization") {
			return true
		}
	}
	return false
}

func secureWebhookTarget(target *url.URL) bool {
	switch target.Scheme {
	case "https":
		return true
	case "http":
		host := target.Hostname()
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}

func writeSidecarAtomically(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
