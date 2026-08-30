package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

// Deliver sends one spooled event to every configured destination and reports whether any
// accepted it.
//
// Best-effort by design: a failed delivery leaves the event in the spool for the next run
// rather than blocking anything. A machine that cannot reach its receiver has still detected
// and repaired the problem, and the only thing outstanding is telling somebody.
func Deliver(config *Config, event Event, envelopeBytes []byte, timeout time.Duration) error {
	if len(config.Destinations) == 0 {
		return ErrNoDestinations
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var failures []string
	accepted := false
	for _, destination := range config.Destinations {
		if err := deliverOne(destination, event, envelopeBytes, timeout); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", destination.Kind, err))
			continue
		}
		accepted = true
	}
	if accepted {
		return nil
	}
	return fmt.Errorf("no destination accepted the event: %s", strings.Join(failures, "; "))
}

func deliverOne(
	destination Destination, event Event, envelopeBytes []byte, timeout time.Duration,
) error {
	body, err := json.Marshal(Notification{
		Text: event.Summary(), Severity: event.Severity, Event: event,
		Envelope: json.RawMessage(envelopeBytes),
	})
	if err != nil {
		return err
	}

	switch destination.Kind {
	case "webhook":
		return postWebhook(destination, body, timeout)
	case "command":
		return runCommand(destination, body, timeout)
	case "file":
		return writeFile(destination, event, envelopeBytes)
	default:
		return fmt.Errorf("unknown destination kind %q", destination.Kind)
	}
}

func postWebhook(destination Destination, body []byte, timeout time.Duration) error {
	if destination.URL == "" {
		return fmt.Errorf("no url")
	}
	context, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(
		context, http.MethodPost, destination.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range destination.Headers {
		request.Header.Set(name, value)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("%s replied %s", destination.URL, response.Status)
	}
	return nil
}

func runCommand(destination Destination, body []byte, timeout time.Duration) error {
	if len(destination.Command) == 0 {
		return fmt.Errorf("no command")
	}
	context, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := exec.CommandContext(context,
		destination.Command[0], destination.Command[1:]...)
	command.Stdin = bytes.NewReader(body)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeFile(destination Destination, event Event, envelopeBytes []byte) error {
	if destination.Directory == "" {
		return fmt.Errorf("no directory")
	}
	if err := os.MkdirAll(destination.Directory, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s-%s.json",
		event.At.UTC().Format("20060102T150405Z"), sanitize(event.Machine), event.Kind)
	return os.WriteFile(filepath.Join(destination.Directory, name), envelopeBytes, 0o600)
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
