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
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
)

// PayloadType keeps an event signature from being replayed as an attestation or a catalog.
const PayloadType = "application/vnd.skilltrust.event.v1+json"

// EventVersion is the payload schema version.
const EventVersion = 1

// CheckPayloadType keeps a current-check signature from being replayed as an event or an
// attestation.
const CheckPayloadType = "application/vnd.skilltrust.check.v1+json"

// CheckVersion is the signed current-check schema version.
const CheckVersion = 1

// Kind is what happened. Only things worth waking someone for are kinds; an unchanged plugin
// produces no event at all, because a stream that reports normality is a stream nobody reads.
type Kind string

const (
	// CheckScopeManaged is the marketplace-managed plugin cache this machine verified.
	CheckScopeManaged = "managed"
	// CheckScopeApprovedSkills is the machine-local approved loose-skill directory this
	// machine verified.
	CheckScopeApprovedSkills = "approved-skills"
	// CheckScopeLoose is a compatibility alias for the same loose-skill surface.
	CheckScopeLoose = "loose"

	// KindRestored means a signed plugin had been changed on this machine and was put back.
	KindRestored Kind = "restored"
	// KindRevoked means a revoked plugin was found installed.
	KindRevoked Kind = "revoked"
	// KindUnverifiable means a signed plugin could not be checked or could not be repaired.
	KindUnverifiable Kind = "unverifiable"
	// KindCatalogUnusable means a marketplace could not be verified, so its plugins went
	// unchecked. Silence about that would be indistinguishable from everything being fine.
	KindCatalogUnusable Kind = "catalog-unusable"
	// KindSkillChanged means a skill no longer matches the approval it was given.
	//
	// It is the loose-skill counterpart of KindRestored and reports something weaker on
	// purpose: nothing was put back. A skill outside a marketplace has no published copy to
	// restore from, so the bytes the agent will read are the changed ones, and all this can
	// do is say so. That is also why it exists at all — for a fleet on Cursor or Antigravity,
	// which install nothing from a marketplace, it is the only event an organisation will
	// ever see about the skills its people actually run.
	KindSkillChanged Kind = "skill-changed"
	// KindAdapted means someone at that machine deliberately kept a change to a signed
	// skill. It is not an incident and nobody should be woken for it, but it is the one
	// case where a machine knowingly runs bytes no publisher signed — so an organisation
	// that cannot see it does not know what its fleet is running.
	KindAdapted Kind = "adapted"
)

const (
	maxMachineNameBytes = 255
	maxHostNameBytes    = 255
	maxCatalogChecks    = 32
	maxCatalogNameBytes = 255
)

// Severity lets a receiver route without parsing the whole event.
func (k Kind) Severity() string {
	switch k {
	case KindRevoked:
		return "high"
	case KindRestored, KindUnverifiable:
		return "medium"
	case KindSkillChanged:
		// Medium, not high. The common cause is the person who approved it editing it
		// again, and high is what a revocation gets — something an organisation withdrew
		// on purpose. Ranking an ordinary edit alongside that is how high stops meaning
		// anything. It is not low either: nothing was put back, so whatever the change
		// was, the agent is reading it.
		return "medium"
	case KindAdapted:
		// Deliberately low. A person chose this, and paging anyone for a choice they made
		// is how a stream stops being read - including the lines that are not choices.
		return "low"
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
	// Skill names a skill that came from no marketplace. Separate from Plugin because they
	// are answerable to different things: a plugin is measured against what a publisher
	// signed, a skill against what somebody on this machine approved, and a console that
	// merged them would be adding up two different claims.
	Skill      string `json:"skill,omitempty"`
	PluginVer  string `json:"plugin_version,omitempty"`
	Sequence   int64  `json:"catalog_sequence,omitempty"`
	Signed     string `json:"signed_digest,omitempty"`
	Found      string `json:"found_digest,omitempty"`
	Quarantine string `json:"quarantine,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// CatalogCheck names one catalog this machine used while producing a current check.
type CatalogCheck struct {
	Name       string    `json:"name"`
	Sequence   int64     `json:"sequence,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitempty"`
}

// CheckResult is one machine's latest signed account of a verification scope.
type CheckResult struct {
	Version    int            `json:"version"`
	Machine    string         `json:"machine"`
	Host       string         `json:"host,omitempty"`
	Scope      string         `json:"scope"`
	Sequence   int64          `json:"sequence"`
	CheckedAt  time.Time      `json:"checked_at"`
	FreshUntil time.Time      `json:"fresh_until,omitempty"`
	Complete   bool           `json:"complete"`
	Checked    int            `json:"checked"`
	Changed    int            `json:"changed,omitempty"`
	Unapproved int            `json:"unapproved,omitempty"`
	Errors     int            `json:"errors,omitempty"`
	Catalogs   []CatalogCheck `json:"catalogs,omitempty"`
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
	case KindAdapted:
		// The reason travels with the event. An organisation reading "runs a modified copy"
		// learns only that it should go and ask; reading why the person changed it usually
		// ends the question there, which is the difference between a useful line and a
		// line that generates work.
		if e.Detail == "" {
			return fmt.Sprintf("%s on %s is a modified copy its owner chose to keep",
				e.Plugin, e.displayHost())
		}
		return fmt.Sprintf("%s on %s is a modified copy its owner chose to keep: %s",
			e.Plugin, e.displayHost(), e.Detail)
	case KindSkillChanged:
		return fmt.Sprintf("%s on %s no longer matches what %s approved",
			e.Skill, e.displayHost(), e.Detail)
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

func (c CheckResult) displayHost() string {
	if c.Host != "" {
		return c.Host
	}
	return c.Machine
}

// Summary is the one line a human reads first from a current-check result.
func (c CheckResult) Summary() string {
	if c.Healthy() {
		return fmt.Sprintf("%s checked %s: %d item(s) matched what was signed",
			c.displayHost(), c.Scope, c.Checked)
	}
	parts := []string{fmt.Sprintf("%d checked", c.Checked)}
	if c.Changed > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", c.Changed))
	}
	if c.Unapproved > 0 {
		parts = append(parts, fmt.Sprintf("%d unapproved", c.Unapproved))
	}
	if c.Errors > 0 {
		parts = append(parts, fmt.Sprintf("%d error(s)", c.Errors))
	}
	if !c.Complete {
		parts = append(parts, "partial")
	}
	if c.FreshUntil.IsZero() {
		parts = append(parts, "freshness unknown")
	} else if !time.Now().UTC().Before(c.FreshUntil) {
		parts = append(parts, "stale")
	}
	return fmt.Sprintf("%s checked %s: %s",
		c.displayHost(), c.Scope, strings.Join(parts, ", "))
}

// Complete fills the fields derived from the kind, so the event that is signed and the event
// that is delivered are the same one. They were briefly not: Sign filled them on its own copy
// and every notification went out with an empty severity, which is the field a receiver
// routes on.
func (e *Event) Complete() {
	e.Version = EventVersion
	e.Severity = e.Kind.Severity()
}

// Healthy reports whether this check is a complete, fresh and issue-free verdict with
// non-zero coverage.
func (c CheckResult) Healthy() bool {
	return c.HealthyAt(time.Now().UTC())
}

// HealthyAt reports whether this check is a complete, still-fresh and issue-free verdict
// with non-zero coverage at the given time.
func (c CheckResult) HealthyAt(now time.Time) bool {
	return c.Complete && !c.FreshUntil.IsZero() && now.Before(c.FreshUntil) && c.Checked > 0 &&
		c.Changed == 0 && c.Unapproved == 0 && c.Errors == 0
}

func (c *CheckResult) complete() error {
	switch {
	case c.Machine == "":
		return fmt.Errorf("check result needs a machine")
	case len(c.Machine) > maxMachineNameBytes:
		return fmt.Errorf("check result machine is too long")
	case len(c.Host) > maxHostNameBytes:
		return fmt.Errorf("check result host is too long")
	case c.Scope == "":
		return fmt.Errorf("check result needs a scope")
	case !ValidCheckScope(c.Scope):
		return fmt.Errorf("check result scope %q is not supported", c.Scope)
	case c.Sequence <= 0:
		return fmt.Errorf("check result needs a positive sequence")
	case c.CheckedAt.IsZero():
		return fmt.Errorf("check result needs a checked_at time")
	case !c.FreshUntil.IsZero() && !c.FreshUntil.After(c.CheckedAt):
		return fmt.Errorf("check result fresh_until must be after checked_at")
	case c.Checked < 0 || c.Changed < 0 || c.Unapproved < 0 || c.Errors < 0:
		return fmt.Errorf("check result counts cannot be negative")
	}
	if len(c.Catalogs) > maxCatalogChecks {
		return fmt.Errorf("check result names too many catalogs")
	}
	for _, catalog := range c.Catalogs {
		switch {
		case catalog.Name == "":
			return fmt.Errorf("check result needs every catalog to have a name")
		case len(catalog.Name) > maxCatalogNameBytes:
			return fmt.Errorf("check result catalog name is too long")
		}
	}
	c.Version = CheckVersion
	return nil
}

// ValidCheckScope bounds current-check storage to the product's supported surfaces.
func ValidCheckScope(scope string) bool {
	switch scope {
	case CheckScopeManaged, CheckScopeApprovedSkills, CheckScopeLoose:
		return true
	default:
		return false
	}
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

// SignCheck wraps a current-check result in a DSSE envelope under the machine's key.
func SignCheck(check CheckResult, key ed25519.PrivateKey) (*attest.Envelope, error) {
	if err := check.complete(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(check)
	if err != nil {
		return nil, err
	}
	return attest.SignPayload(CheckPayloadType, payload, key), nil
}

// VerifyCheck checks a current-check result against a set of machine keys and returns it
// with the signer.
func VerifyCheck(envelope *attest.Envelope, trusted *attest.TrustedKeys) (*CheckResult, string, error) {
	payload, keyID, err := attest.VerifyPayload(envelope, CheckPayloadType, trusted)
	if err != nil {
		return nil, "", err
	}
	var check CheckResult
	if err := json.Unmarshal(payload, &check); err != nil {
		return nil, "", fmt.Errorf("check result payload is not readable: %w", err)
	}
	if check.Version != CheckVersion {
		return nil, "", fmt.Errorf("check result version %d is not understood by this build",
			check.Version)
	}
	if err := check.complete(); err != nil {
		return nil, "", err
	}
	return &check, keyID, nil
}

// Spool is a directory of events waiting to be delivered.
//
// Events are written before delivery is attempted and removed only once every configured
// destination that should receive them has acknowledged them. A machine that is offline,
// or whose receiver is down, accumulates rather than loses: the alternative is that the
// one incident worth hearing about is the one that happened while the VPN was down.
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

// SaveCheck keeps one pending current-check per scope, replacing an older one because the
// latest state is the only thing a receiver needs.
func (s Spool) SaveCheck(envelope *attest.Envelope, scope string) (string, error) {
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(s.Directory, "check-"+sanitize(scope)+".json")
	if err := envelope.Save(path + ".tmp"); err != nil {
		return "", err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		_ = os.Remove(path + ".tmp")
		return "", err
	}
	_ = os.Remove(ackPath(path))
	return path, nil
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
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" &&
			!strings.HasSuffix(entry.Name(), ".acks.json") {
			paths = append(paths, filepath.Join(s.Directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}
