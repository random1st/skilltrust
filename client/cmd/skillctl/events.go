package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
	"github.com/random1st/skilltrust/report"
)

const (
	CheckScopeManaged           = report.CheckScopeManaged
	CheckScopeApprovedSkills    = report.CheckScopeApprovedSkills
	looseCheckFreshnessWindow   = 24 * time.Hour
	managedCheckFreshnessWindow = 24 * time.Hour
)

type CurrentCheck struct {
	Scope      string
	CheckedAt  time.Time
	FreshUntil time.Time
	Complete   bool
	Checked    int
	Changed    int
	Unapproved int
	Errors     int
	Catalogs   []report.CatalogCheck
}

type ReportingStatus struct {
	QueuedEvents    int
	QueuedChecks    int
	DeliveredEvents int
	DeliveredChecks int
	PendingEvents   int
	PendingChecks   int
	CheckDigests    map[string]string
}

func (s *ReportingStatus) add(other ReportingStatus) {
	s.QueuedEvents += other.QueuedEvents
	s.QueuedChecks += other.QueuedChecks
	s.DeliveredEvents += other.DeliveredEvents
	s.DeliveredChecks += other.DeliveredChecks
	s.PendingEvents += other.PendingEvents
	s.PendingChecks += other.PendingChecks
	if len(other.CheckDigests) == 0 {
		return
	}
	if s.CheckDigests == nil {
		s.CheckDigests = make(map[string]string, len(other.CheckDigests))
	}
	for scope, digest := range other.CheckDigests {
		s.CheckDigests[scope] = digest
	}
}

// skillDrift is one skill whose bytes stopped matching its approval.
type skillDrift struct {
	Name       string
	ApprovedBy string
	Approved   string
	OnDisk     string
}

type queuedReport struct {
	path  string
	body  []byte
	event *report.Event
	check *report.CheckResult
}

func reportConfigPath() string { return homePath("reporting.json") }
func spool() report.Spool      { return report.Spool{Directory: homePath("events")} }

// machineName identifies this machine in a report. The hostname is the name whoever reads an
// alert already knows the machine by; a generated identifier would be correct and useless.
func machineName(config *report.Config) string {
	if config != nil && config.Machine != "" {
		return config.Machine
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "unknown"
}

// recordEvents turns a reconciliation into signed events and tries to deliver them.
func recordEvents(results []marketplace.Result, unusable []string, now time.Time) {
	_, _ = recordReports(collectEvents(results, unusable, now), nil, 0)
}

// recordSkillDrift reports skills that no longer match the approval they were given.
func recordSkillDrift(drift []skillDrift, now time.Time) {
	_, _ = recordReports(skillDriftEvents(drift, now), nil, 0)
}

// recordManagedCheck turns the latest managed-plugin state into one signed current-check
// record and tries to deliver it.
func recordManagedCheck(managed ManagedCheck) {
	_, _ = recordCurrentChecks(0, managedCurrentCheck(managed))
}

func recordCurrentChecks(deliveryBudget time.Duration, checks ...CurrentCheck) (ReportingStatus, error) {
	return recordReports(nil, checks, deliveryBudget)
}

func recordReports(
	events []report.Event, checks []CurrentCheck, deliveryBudget time.Duration,
) (ReportingStatus, error) {
	config, configErr := report.LoadConfig(reportConfigPath())
	machine := machineName(config)
	deadline, lockBudget := reportingDeadline(deliveryBudget)

	var status ReportingStatus
	var errs []error
	if configErr != nil {
		errs = append(errs, configErr)
	}

	if len(events) > 0 || len(checks) > 0 {
		key, keyErr := attest.LoadPrivateKey(defaultSigningKey())
		if keyErr != nil {
			errs = append(errs, fmt.Errorf("no machine key, so %d report%s could not be signed; run `skillctl init`: %w",
				len(events)+len(checks), plural(len(events)+len(checks), "", "s"), keyErr))
		} else {
			queued, err := queueEvents(events, key, machine)
			status.add(queued)
			if err != nil {
				errs = append(errs, err)
			}
			locked, err := recordChecksAndFlush(config, checks, key, machine, deadline, lockBudget)
			status.add(locked)
			if err != nil {
				errs = append(errs, err)
			}
			return status, errors.Join(errs...)
		}
	}

	locked, err := recordChecksAndFlush(config, nil, nil, machine, deadline, lockBudget)
	status.add(locked)
	if err != nil {
		errs = append(errs, err)
	}
	return status, errors.Join(errs...)
}

// FlushPendingEventReports retries every spooled event and current-check.
func FlushPendingEventReports(timeout time.Duration) (ReportingStatus, error) {
	var status ReportingStatus
	deadline, lockBudget := reportingDeadline(timeout)
	err := withReportingLock(lockBudget, func() error {
		config, err := report.LoadConfig(reportConfigPath())
		if err != nil {
			pending, pendingErr := pendingReportStatus()
			status.add(pending)
			if pendingErr != nil {
				return errors.Join(err, pendingErr)
			}
			return err
		}
		remaining, ok := remainingReportingBudget(deadline)
		if deadline.IsZero() {
			remaining = timeout
			ok = true
		}
		if !ok {
			pending, pendingErr := pendingReportStatus()
			status.add(pending)
			return errors.Join(errReportingBusy, pendingErr)
		}
		flushed, err := flushPendingEventReportsLocked(config, remaining)
		status.add(flushed)
		return err
	})
	return status, err
}

var errReportingBusy = fmt.Errorf("reporting is busy")

func withReportingLock(timeout time.Duration, run func() error) error {
	path := homePath("reporting.lock")
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	const staleAfter = 2 * time.Minute
	for {
		if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > staleAfter {
			_ = os.Remove(path)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
			_ = file.Close()
			defer os.Remove(path)
			return run()
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if time.Now().After(deadline) {
			return errReportingBusy
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func queueEvents(
	events []report.Event, key ed25519.PrivateKey, machine string,
) (ReportingStatus, error) {
	var status ReportingStatus
	var errs []error
	for _, event := range events {
		event.Machine = machine
		event.Host = machine
		envelope, err := report.Sign(event, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := spool().Add(envelope, event.At, string(event.Kind)); err != nil {
			errs = append(errs, err)
			continue
		}
		status.QueuedEvents++
	}
	return status, errors.Join(errs...)
}

func queueChecks(
	checks []CurrentCheck, key ed25519.PrivateKey, machine string,
) (ReportingStatus, error) {
	var status ReportingStatus
	var errs []error
	for _, check := range checks {
		result, envelope, err := signCurrentCheck(check, machine, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := spool().SaveCheck(envelope, result.Scope); err != nil {
			errs = append(errs, err)
			continue
		}
		status.QueuedChecks++
		body, err := os.ReadFile(filepath.Join(spool().Directory, "check-"+sanitizeScope(result.Scope)+".json"))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if status.CheckDigests == nil {
			status.CheckDigests = map[string]string{}
		}
		status.CheckDigests[result.Scope] = digestHex(body)
		// Keep the exact signed bytes after the queue removes a delivered check.
		// Status can then bind the receipt to this result instead of trusting a
		// receipt alone or counting configured subscriptions as successful setup.
		if err := writeOwnerOnlyFileAtomically(latestCheckPath(result.Scope), body); err != nil {
			errs = append(errs, err)
		}
	}
	return status, errors.Join(errs...)
}

func recordChecksAndFlush(
	config *report.Config,
	checks []CurrentCheck,
	key ed25519.PrivateKey,
	machine string,
	deadline time.Time,
	lockBudget time.Duration,
) (ReportingStatus, error) {
	var status ReportingStatus
	err := withReportingLock(lockBudget, func() error {
		var errs []error
		if len(checks) > 0 && key != nil {
			queued, err := queueChecks(checks, key, machine)
			status.add(queued)
			if err != nil {
				errs = append(errs, err)
			}
		}

		remaining, ok := remainingReportingBudget(deadline)
		if deadline.IsZero() {
			remaining = 0
			ok = true
		}
		if ok {
			flushed, err := flushPendingEventReportsLocked(config, remaining)
			status.add(flushed)
			if err != nil {
				errs = append(errs, err)
			}
		} else {
			pending, err := pendingReportStatus()
			status.add(pending)
			errs = append(errs, errReportingBusy)
			if err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
	return status, err
}

func reportingDeadline(budget time.Duration) (time.Time, time.Duration) {
	if budget <= 0 {
		return time.Time{}, 5 * time.Second
	}
	return time.Now().Add(budget), budget
}

func remainingReportingBudget(deadline time.Time) (time.Duration, bool) {
	if deadline.IsZero() {
		return 0, true
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, false
	}
	return remaining, true
}

func signCurrentCheck(
	check CurrentCheck, machine string, key ed25519.PrivateKey,
) (report.CheckResult, *attest.Envelope, error) {
	checkedAt := check.CheckedAt.UTC()
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	scope := normalizeCheckScope(check.Scope)
	sequence, err := nextCheckSequence(scope, checkedAt)
	if err != nil {
		return report.CheckResult{}, nil, err
	}
	result := report.CheckResult{
		Machine:    machine,
		Host:       machine,
		Scope:      scope,
		Sequence:   sequence,
		CheckedAt:  checkedAt,
		FreshUntil: check.FreshUntil,
		Complete:   check.Complete,
		Checked:    check.Checked,
		Changed:    check.Changed,
		Unapproved: check.Unapproved,
		Errors:     check.Errors,
		Catalogs:   append([]report.CatalogCheck(nil), check.Catalogs...),
	}
	envelope, err := report.SignCheck(result, key)
	return result, envelope, err
}

func normalizeCheckScope(scope string) string {
	scope = strings.TrimSpace(scope)
	switch scope {
	case "":
		return CheckScopeManaged
	case report.CheckScopeLoose:
		return CheckScopeApprovedSkills
	default:
		return scope
	}
}

func checkSequencePath(scope string) string {
	return statePath("check-" + sanitizeScope(scope))
}

func sanitizeScope(scope string) string {
	scope = normalizeCheckScope(scope)
	if scope == "" {
		return CheckScopeManaged
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, scope)
}

func nextCheckSequence(scope string, now time.Time) (int64, error) {
	path := checkSequencePath(scope)
	state, err := catalog.LoadState(path)
	if err != nil {
		return 0, err
	}
	next := state.Sequence + 1
	if next < 1 {
		next = 1
	}
	if err := state.Save(path, next, now); err != nil {
		return 0, err
	}
	return next, nil
}

func flushPendingEventReportsLocked(
	config *report.Config, timeout time.Duration,
) (ReportingStatus, error) {
	status, err := pendingReportStatus()
	if err != nil {
		return status, err
	}
	if status.PendingEvents == 0 && status.PendingChecks == 0 {
		return status, nil
	}
	if config == nil || len(config.Destinations) == 0 {
		return status, report.ErrNoDestinations
	}
	if timeout <= 0 {
		timeout = config.Timeout
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	public, err := reportingPublicKey()
	if err != nil {
		return status, err
	}
	trusted := attest.NewTrustedKeys(public)
	pending, err := spool().Pending()
	if err != nil {
		return status, err
	}

	status.PendingEvents = 0
	status.PendingChecks = 0
	var errs []error
	for i, path := range pending {
		remaining, ok := remainingReportingBudget(deadline)
		if !ok {
			countPendingReports(&status, pending[i:])
			errs = append(errs, context.DeadlineExceeded)
			break
		}
		queued, err := readQueuedReport(path, trusted)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			countPendingReport(&status, path)
			continue
		}
		if err := deliverQueuedReport(config, queued, remaining); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			countPendingReport(&status, path)
			continue
		}
		_ = os.Remove(path)
		if queued.check != nil {
			status.DeliveredChecks++
			continue
		}
		status.DeliveredEvents++
	}
	return status, errors.Join(errs...)
}

func pendingReportStatus() (ReportingStatus, error) {
	pending, err := spool().Pending()
	if err != nil {
		return ReportingStatus{}, err
	}
	var status ReportingStatus
	for _, path := range pending {
		countPendingReport(&status, path)
	}
	return status, nil
}

func countPendingReport(status *ReportingStatus, path string) {
	if strings.HasPrefix(filepath.Base(path), "check-") {
		status.PendingChecks++
		return
	}
	status.PendingEvents++
}

func countPendingReports(status *ReportingStatus, paths []string) {
	for _, path := range paths {
		countPendingReport(status, path)
	}
}

func digestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func readQueuedReport(path string, trusted *attest.TrustedKeys) (queuedReport, error) {
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		return queuedReport{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return queuedReport{}, err
	}
	queued := queuedReport{path: path, body: body}
	switch envelope.PayloadType {
	case report.PayloadType:
		event, _, err := report.Verify(envelope, trusted)
		if err != nil {
			return queuedReport{}, err
		}
		queued.event = event
		return queued, nil
	case report.CheckPayloadType:
		check, _, err := report.VerifyCheck(envelope, trusted)
		if err != nil {
			return queuedReport{}, err
		}
		queued.check = check
		return queued, nil
	default:
		return queuedReport{}, fmt.Errorf("unknown report payload type %q", envelope.PayloadType)
	}
}

func deliverQueuedReport(config *report.Config, queued queuedReport, timeout time.Duration) error {
	if queued.check != nil {
		if err := report.DeliverQueuedCheck(queued.path, config, *queued.check, queued.body, timeout); err != nil {
			return err
		}
		// An approved-skills check or event may be delivered next. Preserve the
		// exact receipt for this scope so that delivery cannot erase another
		// scope's evidence and make a healthy connection appear unfinished.
		if body, err := os.ReadFile(connectStatusPath()); err == nil {
			var receipt connectStatusFile
			if json.Unmarshal(body, &receipt) == nil && receipt.Digest == digestHex(queued.body) {
				return writeOwnerOnlyFileAtomically(latestCheckReceiptPath(queued.check.Scope), body)
			}
		}
		return nil
	}
	return report.DeliverQueuedEvent(queued.path, config, *queued.event, queued.body, timeout)
}

func skillDriftEvents(drift []skillDrift, now time.Time) []report.Event {
	events := make([]report.Event, 0, len(drift))
	for _, one := range drift {
		events = append(events, report.Event{
			Kind: report.KindSkillChanged, At: now,
			Skill: one.Name, Signed: one.Approved, Found: one.OnDisk,
			Detail: one.ApprovedBy,
		})
	}
	return events
}

func managedCurrentCheck(managed ManagedCheck) CurrentCheck {
	catalogs := make([]report.CatalogCheck, 0, len(managed.Catalogs))
	var freshUntil time.Time
	for _, one := range managed.Catalogs {
		if one.Sequence == 0 && one.ValidUntil.IsZero() {
			continue
		}
		catalogs = append(catalogs, report.CatalogCheck{
			Name: one.Name, Sequence: one.Sequence, ValidUntil: one.ValidUntil,
		})
		if !one.ValidUntil.IsZero() && (freshUntil.IsZero() || one.ValidUntil.Before(freshUntil)) {
			freshUntil = one.ValidUntil
		}
	}

	checked, changed, failures := 0, 0, len(managed.Unusable)
	for _, result := range managed.Results {
		if result.Outcome == marketplace.OutcomeAbsent {
			continue
		}
		checked++
		switch result.Outcome {
		case marketplace.OutcomeChanged,
			marketplace.OutcomeOtherVersion,
			marketplace.OutcomeRevoked,
			marketplace.OutcomeAdapted:
			changed++
		case marketplace.OutcomeUnverifiable:
			failures++
		}
	}

	checkedAt := managed.CheckedAt.UTC()
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	freshUntil = clampCheckFreshness(freshUntil, checkedAt)
	return CurrentCheck{
		Scope:      normalizeCheckScope(managed.Scope),
		CheckedAt:  checkedAt,
		FreshUntil: freshUntil,
		Complete:   managed.Complete,
		Checked:    checked,
		Changed:    changed,
		Errors:     failures,
		Catalogs:   catalogs,
	}
}

func looseSkillCurrentCheck(loose LooseSkillCheck) CurrentCheck {
	checkedAt := loose.CheckedAt.UTC()
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	return CurrentCheck{
		Scope:      normalizeCheckScope(loose.Scope),
		CheckedAt:  checkedAt,
		FreshUntil: checkedAt.Add(looseCheckFreshnessWindow),
		Complete:   loose.Complete,
		Checked:    loose.Checked,
		Changed:    loose.Changed,
		Unapproved: loose.Unapproved,
		Errors:     loose.Errors,
	}
}

func shouldReportLooseSkillCheck(check LooseSkillCheck) bool {
	return check.Checked > 0 || check.Changed > 0 || check.Unapproved > 0 || check.Errors > 0
}

func clampCheckFreshness(freshUntil, checkedAt time.Time) time.Time {
	if freshUntil.IsZero() {
		return time.Time{}
	}
	limit := checkedAt.Add(managedCheckFreshnessWindow)
	if freshUntil.After(limit) {
		return limit
	}
	return freshUntil
}

func reportingPublicKey() (ed25519.PublicKey, error) {
	public, err := attest.LoadPublicKey(defaultPublicKey())
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return public, err
	}
	private, err := attest.LoadPrivateKey(defaultSigningKey())
	if err != nil {
		return nil, err
	}
	publicKey, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s does not hold an ed25519 key", defaultSigningKey())
	}
	return publicKey, nil
}

// collectEvents keeps only what is worth waking someone for. An unchanged plugin produces
// nothing, because a stream that reports normality is a stream nobody reads.
func collectEvents(results []marketplace.Result, unusable []string, now time.Time) []report.Event {
	var events []report.Event

	for _, result := range results {
		kind, ok := kindFor(result.Outcome)
		if !ok {
			continue
		}
		// An adoption's reason is the whole value of reporting it, so it travels as the
		// event's detail rather than being left behind in a field the report does not carry.
		detail := result.Detail
		if result.Outcome == marketplace.OutcomeAdapted {
			detail = result.Adapted
			if !result.AdaptedSince.IsZero() {
				detail = fmt.Sprintf("%s (adopted %s)", result.Adapted, age(result.AdaptedSince, now))
			}
		}
		events = append(events, report.Event{
			Kind: kind, At: now,
			Marketplace: result.Marketplace, Plugin: result.Plugin, PluginVer: result.Version,
			Signed: result.Signed, Found: result.OnDisk,
			Quarantine: result.Quarantine, Detail: detail,
		})
	}
	for _, failure := range unusable {
		events = append(events, report.Event{
			Kind: report.KindCatalogUnusable, At: now, Detail: failure,
		})
	}
	return events
}

func kindFor(outcome marketplace.Outcome) (report.Kind, bool) {
	switch outcome {
	case marketplace.OutcomeRestored:
		return report.KindRestored, true
	case marketplace.OutcomeRevoked:
		return report.KindRevoked, true
	case marketplace.OutcomeChanged, marketplace.OutcomeUnverifiable:
		return report.KindUnverifiable, true
	case marketplace.OutcomeAdapted:
		return report.KindAdapted, true
	default:
		return "", false
	}
}
