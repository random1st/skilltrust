package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/enrollment"
	"github.com/random1st/skilltrust/internal/source"
	"github.com/random1st/skilltrust/report"
)

const (
	connectRecordVersion    = 1
	connectPendingVersion   = 1
	connectStatusVersion    = 1
	connectDefaultBaseURL   = "https://axela.app"
	connectDefaultWait      = 45 * time.Second
	connectMaxWait          = time.Minute
	connectTimeout          = 3 * time.Second
	connectMaxResponseBytes = 256 << 10
	reportTimeoutSeconds    = 2
)

var (
	connectNow         = func() time.Time { return time.Now().UTC() }
	connectSleep       = time.Sleep
	connectOpenBrowser = openBrowser
)

type pendingConnect struct {
	Version      int              `json:"version"`
	Audience     string           `json:"audience"`
	Machine      string           `json:"machine"`
	MachineKeyID string           `json:"machine_key_id,omitempty"`
	Token        string           `json:"token"`
	Envelope     *attest.Envelope `json:"envelope"`
	RequestedAt  time.Time        `json:"requested_at"`
	Expired      bool             `json:"-"`
	Resuming     bool             `json:"-"`
}

type savedConnect struct {
	Version       int                  `json:"version"`
	Audience      string               `json:"audience"`
	Organisation  string               `json:"organisation"`
	Machine       string               `json:"machine"`
	MachineKeyID  string               `json:"machine_key_id"`
	IngestURL     string               `json:"ingest_url"`
	DashboardURL  string               `json:"dashboard_url"`
	PublisherKeys []string             `json:"publisher_keys,omitempty"`
	NotaryKeys    []string             `json:"notary_keys,omitempty"`
	Catalogs      []enrollment.Catalog `json:"catalogs,omitempty"`
	ConnectedAt   time.Time            `json:"connected_at"`
}

type connectStatusFile struct {
	Version     int    `json:"version"`
	AcceptedURL string `json:"accepted_url,omitempty"`
	AcceptedAt  string `json:"accepted_at,omitempty"`
	Signer      string `json:"signer,omitempty"`
	Digest      string `json:"digest,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type connectSummary struct {
	status    string
	attention []string
	checked   bool
	verified  bool
	installed []string
}

type connectBlocked struct{ message string }

func (e connectBlocked) Error() string { return e.message }

func runConnect(args []string) int {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: skillctl connect [flags] [https://axela.example]\n\n"+
			"Starts or resumes this computer's browser-approved Axela connection. It creates\n"+
			"or reuses the machine key, opens the approval URL, stores the report credential\n"+
			"locally, follows the organisation's catalogs, installs session hooks for managed\n"+
			"clients found on this machine, and waits briefly for approval. Without an\n"+
			"address it connects to %s.\n\n"+
			"Exit codes: %d connected and acknowledged, %d pending or needs attention, %d error.\n\nFlags:\n",
			connectDefaultBaseURL, exitClean, exitFindings, exitUsage)
		flags.PrintDefaults()
	}

	machine := flags.String("machine", "", "short name for this computer; defaults to the hostname")
	noBrowser := flags.Bool("no-browser", false, "print the approval URL instead of opening it")
	wait := flags.Duration("wait", connectDefaultWait, "how long to wait for browser approval before returning")

	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() > 1 {
		flags.Usage()
		return exitUsage
	}
	if *wait < 0 || *wait > connectMaxWait {
		fmt.Fprintf(os.Stderr, "skillctl: -wait must be between 0 and %s\n", connectMaxWait)
		return exitUsage
	}

	now := connectNow()
	current, err := loadSavedConnect()
	if err != nil {
		return fail(err)
	}
	var pending *pendingConnect
	if current == nil {
		pending, err = loadPendingConnect(now)
		if err != nil {
			return fail(err)
		}
	}

	base, err := resolveConnectBase(flags.Arg(0), pending, current)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl: %v\n", err)
		return exitUsage
	}

	var connection *enrollment.Connection
	created := false
	if current != nil {
		pending, connection, err = resumeSavedConnect(base, current)
	} else {
		pending, created, err = ensurePendingConnect(base, *machine, pending, now)
		if err == nil && pending.Expired {
			pending, created, err = createPendingConnect(base, pending.Machine, now)
		}
	}
	if err != nil {
		return fail(err)
	}

	fmt.Printf("service     %s\n", base)
	fmt.Printf("machine     %s\n", pending.Machine)
	fmt.Printf("key         %s\n", attest.Fingerprint(pending.MachineKeyID))

	pendingApproval := false
	if connection == nil {
		connection, pendingApproval, err = pollConnectStatus(base, pending)
	}
	if err != nil {
		if blocked, ok := err.(connectBlocked); ok {
			fmt.Printf("status      needs attention\n")
			fmt.Printf("attention   %s\n", blocked.message)
			fmt.Printf("continue    finish the organisation setup in Axela, then run skillctl connect again\n")
			return exitFindings
		}
		return fail(err)
	}

	if connection == nil {
		approvalURL, err := approvalURL(base, pending.Envelope)
		if err != nil {
			return fail(err)
		}
		if *noBrowser {
			fmt.Printf("approval    %s\n", approvalURL)
		} else if created {
			if err := connectOpenBrowser(approvalURL); err != nil {
				fmt.Printf("approval    %s\n", approvalURL)
				fmt.Fprintf(os.Stderr, "skillctl: could not open the browser automatically: %v\n", err)
			} else {
				fmt.Printf("approval    opened in your browser\n")
			}
		} else {
			fmt.Printf("approval    %s\n", approvalURL)
		}

		connection, pendingApproval, err = pollUntilConnected(base, pending, *wait)
		if err != nil {
			if blocked, ok := err.(connectBlocked); ok {
				fmt.Printf("status      needs attention\n")
				fmt.Printf("attention   %s\n", blocked.message)
				fmt.Printf("continue    finish the organisation setup in Axela, then run skillctl connect again\n")
				return exitFindings
			}
			return fail(err)
		}
		if pendingApproval {
			fmt.Printf("status      pending\n")
			fmt.Printf("continue    finish approval in the browser tab above, then run skillctl connect again\n")
			return exitFindings
		}
	}

	summary, err := applyConnected(base, pending, connection)
	if err != nil {
		return fail(err)
	}

	fmt.Printf("organisation %s\n", connection.Organisation)
	if connection.DashboardURL != "" {
		fmt.Printf("dashboard   %s\n", connection.DashboardURL)
	}
	if len(summary.installed) > 0 {
		fmt.Printf("hooks       %s\n", strings.Join(summary.installed, ", "))
	}
	for _, name := range summary.installed {
		if name == "codex" {
			fmt.Println("hook trust  approve the SkillTrust hook in Codex if prompted; automatic session checks require that approval")
		}
	}
	if summary.status == "" {
		summary.status = "connected"
	}
	fmt.Printf("status      %s\n", summary.status)
	for _, line := range summary.attention {
		fmt.Printf("attention   %s\n", line)
	}
	if summary.status != "connected" {
		fmt.Printf("continue    run skillctl connect again after the attention items above\n")
		return exitFindings
	}
	return exitClean
}

func applyConnected(base string, pending *pendingConnect, connection *enrollment.Connection) (connectSummary, error) {
	if err := validateConnection(base, pending, connection); err != nil {
		return connectSummary{}, err
	}
	var attention []string
	if !pending.Resuming {
		var err error
		attention, err = saveBootstrapSubscriptions(base, connection)
		if err != nil {
			return connectSummary{}, err
		}
	}
	record := &savedConnect{
		Version:       connectRecordVersion,
		Audience:      base,
		Organisation:  connection.Organisation,
		Machine:       pending.Machine,
		MachineKeyID:  connection.MachineKeyID,
		IngestURL:     connection.IngestURL,
		DashboardURL:  connection.DashboardURL,
		PublisherKeys: append([]string(nil), connection.PublisherKeys...),
		NotaryKeys:    append([]string(nil), connection.NotaryKeys...),
		Catalogs:      append([]enrollment.Catalog(nil), connection.Catalogs...),
		ConnectedAt:   connectNow(),
	}
	if err := writeOwnerOnlyText(connectCredentialsPath(), pending.Token+"\n"); err != nil {
		return connectSummary{}, err
	}
	if err := saveHomeJSON(connectStatusPath(), connectStatusFile{Version: connectStatusVersion}); err != nil {
		return connectSummary{}, err
	}
	if err := configureReporting(pending.Machine, connection.IngestURL); err != nil {
		return connectSummary{}, err
	}

	// Store resumable public configuration only after bootstrap succeeds. An empty
	// team must still obtain its first published catalog on the next approval poll.
	if len(attention) == 0 && len(connection.Catalogs) > 0 {
		if err := saveHomeJSON(connectStatePath(), record); err != nil {
			return connectSummary{}, err
		}
	}

	installed, hookNotes := installManagedHooks()
	attention = append(attention, hookNotes...)
	checked, verified, checkNotes := runFirstCheck()
	attention = append(attention, checkNotes...)

	status := "connected"
	if len(attention) > 0 || !checked || !verified {
		status = "needs attention"
	}
	return connectSummary{
		status:    status,
		attention: attention,
		checked:   checked,
		verified:  verified,
		installed: installed,
	}, nil
}

func runFirstCheck() (bool, bool, []string) {
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return false, false, []string{fmt.Sprintf("the first check could not load the followed catalogs: %v", err)}
	}
	if len(subscriptions) == 0 {
		return false, false, []string{"this organisation has no followed catalog yet, so the first check is still pending"}
	}

	agent, ok := preferredManagedAgent(detectManagedAgents())
	if !ok {
		return false, false, []string{"no managed Claude Code or Codex home was found, so there was nowhere to run the first marketplace check"}
	}

	managed, code := RunManagedCheck(agent.Home(), ManagedCheckOptions{
		Restore: true, Offline: false, UpdateSource: true, RefreshBudget: 3 * time.Second,
	})
	if code != exitClean {
		return false, false, []string{"the first check did not finish cleanly; run skillctl connect again after fixing the local setup"}
	}
	reportManaged := aggregateManagedReportCheck(managed, agent.Home(), agent.Name, "")
	check := managedCurrentCheck(reportManaged)
	var installNotes []string
	if check.Checked == 0 && len(reportManaged.Unusable) == 0 {
		if err := ensureFirstManagedPlugin(agent); err != nil {
			installNotes = append(installNotes, err.Error())
		} else {
			managed, code = RunManagedCheck(agent.Home(), ManagedCheckOptions{Restore: true, Offline: true})
			if code != exitClean {
				return false, false, []string{"the installed plugin could not be checked; run skillctl connect again"}
			}
			reportManaged = aggregateManagedReportCheck(managed, agent.Home(), agent.Name, "")
			check = managedCurrentCheck(reportManaged)
		}
	}
	status, err := recordReports(
		collectEvents(managed.Results, managed.Unusable, connectNow()),
		[]CurrentCheck{check},
		time.Duration(reportTimeoutSeconds)*time.Second,
	)

	notes := make([]string, 0, len(reportManaged.Unusable)+4)
	notes = append(notes, installNotes...)
	for _, failure := range reportManaged.Unusable {
		notes = append(notes, "a followed catalog could not be checked: "+failure)
	}
	if err != nil {
		notes = append(notes, fmt.Sprintf("the first check could not be reported yet: %v", err))
	}
	if status.PendingChecks > 0 {
		notes = appendUniqueConnectNote(notes, receiptStatusNote())
	}

	checked := check.Checked > 0
	if !checked {
		notes = append(notes, "no signed plugin from the followed catalogs is installed in the managed clients yet")
		return false, false, notes
	}
	if !check.Complete || check.Changed > 0 || check.Unapproved > 0 || check.Errors > 0 || !check.FreshUntil.After(connectNow()) {
		notes = append(notes, "the first check needs attention; run skillctl sync to review the findings, then skillctl connect again")
		return true, false, notes
	}
	public, keyErr := reportingPublicKey()
	config, configErr := report.LoadConfig(reportConfigPath())
	accepted := false
	if keyErr == nil && configErr == nil {
		for _, destination := range config.Destinations {
			if destination.ReceiptFile == connectStatusPath() && destination.BearerTokenFile == connectCredentialsPath() {
				accepted = receiptAccepted(status.CheckDigests[CheckScopeManaged], attest.KeyID(public), destination.URL)
				break
			}
		}
	}
	if !accepted {
		notes = appendUniqueConnectNote(notes, receiptStatusNote())
		return true, false, notes
	}
	return true, true, notes
}

func receiptStatusNote() string {
	return "Axela has not acknowledged the first check yet"
}

func receiptAccepted(expectedDigest, expectedSigner, expectedURL string) bool {
	if expectedDigest == "" || expectedSigner == "" || expectedURL == "" {
		return false
	}
	raw, err := os.ReadFile(connectStatusPath())
	if err != nil {
		return false
	}
	var status connectStatusFile
	if json.Unmarshal(raw, &status) != nil {
		return false
	}
	if status.AcceptedURL != expectedURL || status.Signer != expectedSigner || status.Digest != expectedDigest {
		return false
	}
	acceptedAt, err := time.Parse(time.RFC3339, status.AcceptedAt)
	return err == nil && !acceptedAt.After(connectNow().Add(5*time.Minute)) && acceptedAt.After(connectNow().Add(-5*time.Minute))
}

func saveBootstrapSubscriptions(base string, connection *enrollment.Connection) ([]string, error) {
	var attention []string
	if len(connection.Catalogs) == 0 {
		return []string{"this organisation has no signed catalog yet"}, nil
	}
	if len(connection.PublisherKeys) == 0 {
		return []string{"this organisation has no publisher key yet"}, nil
	}

	subscriptions, err := loadSubscriptions()
	if err != nil {
		return nil, err
	}
	pins, err := attest.PinnedKeys(defaultTrustedKeys())
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	for _, listed := range connection.Catalogs {
		name := listed.Name
		if name == "" {
			name = source.NameFor(listed.Repository)
		}
		if !catalogNameOK.MatchString(name) {
			return nil, fmt.Errorf("catalog %q is not a usable local name", name)
		}
		if strings.TrimSpace(listed.Repository) == "" {
			return nil, fmt.Errorf("catalog %q has no repository", name)
		}
		if listed.URL == "" {
			return nil, fmt.Errorf("%s has no countersigned catalog URL; connection will not weaken publisher and notary verification", name)
		}
		repositoryURL, err := url.Parse(listed.Repository)
		if err != nil || repositoryURL.Scheme != "https" || repositoryURL.Host == "" || repositoryURL.User != nil || repositoryURL.RawQuery != "" || repositoryURL.Fragment != "" {
			return nil, fmt.Errorf("%s has an unusable repository URL", name)
		}
		hosted := true
		if listed.URL != "" {
			catalogURL, err := canonicalServiceURL(listed.URL, "catalog URL")
			if err != nil {
				return nil, err
			}
			parsed, err := url.Parse(catalogURL)
			if err != nil {
				return nil, err
			}
			if parsed.Scheme != baseURL.Scheme || parsed.Host != baseURL.Host {
				return nil, fmt.Errorf("Axela returned a catalog URL on another origin")
			}
		}
		if hosted && len(connection.NotaryKeys) == 0 {
			attention = append(attention,
				fmt.Sprintf("%s is waiting for its notary key before this machine can follow it", name))
			continue
		}

		var keyIDs []string
		var parties map[string][]string
		for index, encoded := range connection.PublisherKeys {
			label := "catalog:" + name
			if len(connection.PublisherKeys) > 1 {
				label = fmt.Sprintf("%s:%d", label, index+1)
			}
			key, err := parseConnectKey(encoded)
			if err != nil {
				return nil, err
			}
			if existing, ok := pins[label]; ok && !bytes.Equal(existing, key) {
				return nil, fmt.Errorf("%s already pins another key; review the trust change explicitly", label)
			}
			pins[label] = key
			keyID := attest.KeyID(key)
			keyIDs = append(keyIDs, keyID)
			if len(connection.PublisherKeys) > 1 || hosted {
				if parties == nil {
					parties = map[string][]string{}
				}
				parties["publisher"] = append(parties["publisher"], keyID)
			}
		}

		for index, encoded := range connection.NotaryKeys {
			label := "notary:" + name
			if len(connection.NotaryKeys) > 1 {
				label = fmt.Sprintf("%s:%d", label, index+1)
			}
			key, err := parseConnectKey(encoded)
			if err != nil {
				return nil, err
			}
			if existing, ok := pins[label]; ok && !bytes.Equal(existing, key) {
				return nil, fmt.Errorf("%s already pins another key; review the trust change explicitly", label)
			}
			pins[label] = key
			if parties == nil {
				parties = map[string][]string{}
			}
			parties[notaryParty] = append(parties[notaryParty], attest.KeyID(key))
			keyIDs = append(keyIDs, attest.KeyID(key))
		}

		threshold := 1
		if hosted {
			threshold = 2
		}
		entry := Subscription{
			Name:       name,
			Repository: listed.Repository,
			Ref:        listed.Ref,
			CatalogURL: listed.URL,
			KeyIDs:     keyIDs,
			Threshold:  threshold,
			Parties:    parties,
		}
		if err := upsertBootstrapSubscription(&subscriptions, entry); err != nil {
			return nil, err
		}
	}
	encodedPins := map[string]string{}
	for label, key := range pins {
		encoded, err := attest.EncodePublicKey(key)
		if err != nil {
			return nil, err
		}
		encodedPins[label] = string(encoded)
	}
	if err := saveHomeJSON(defaultTrustedKeys(), struct {
		Version int               `json:"version"`
		Keys    map[string]string `json:"keys"`
	}{Version: 1, Keys: encodedPins}); err != nil {
		return nil, err
	}
	return attention, saveBootstrapSubscriptionsFile(subscriptions)
}

func upsertBootstrapSubscription(subscriptions *[]Subscription, entry Subscription) error {
	for index, existing := range *subscriptions {
		if existing.Name != entry.Name {
			continue
		}
		merged, err := mergeBootstrapSubscription(existing, entry)
		if err != nil {
			return err
		}
		(*subscriptions)[index] = merged
		return nil
	}
	*subscriptions = append(*subscriptions, entry)
	return nil
}

func mergeBootstrapSubscription(existing, entry Subscription) (Subscription, error) {
	if existing.Repository != entry.Repository || existing.Ref != entry.Ref || existing.CatalogURL != entry.CatalogURL {
		return Subscription{}, fmt.Errorf("%s already follows a different repository, ref or catalog URL; review the subscription change explicitly", entry.Name)
	}
	oldKeys := append([]string(nil), existing.Keys()...)
	newKeys := append([]string(nil), entry.Keys()...)
	sort.Strings(oldKeys)
	sort.Strings(newKeys)
	if strings.Join(oldKeys, "\n") != strings.Join(newKeys, "\n") {
		return Subscription{}, fmt.Errorf("%s already pins different signing keys; use the signed key rotation or review the trust change explicitly", entry.Name)
	}
	if err := assertBootstrapPartiesCompatible(existing, entry); err != nil {
		return Subscription{}, err
	}
	if existing.Required() > entry.Required() {
		return Subscription{}, fmt.Errorf("%s already requires %d signer(s); skillctl connect will not weaken it to %d",
			entry.Name, existing.Required(), entry.Required())
	}
	entry.Parties = mergeParties(existing.Parties, entry.Parties, entry.Keys())
	entry.KeysSeen = existing.KeysSeen
	if entry.Required() > entry.signerCount() {
		return Subscription{}, fmt.Errorf("%s requires %d signer(s) but only %d remain pinned",
			entry.Name, entry.Required(), entry.signerCount())
	}
	return entry, nil
}

func assertBootstrapPartiesCompatible(existing, entry Subscription) error {
	current := partyAssignments(existing.Parties)
	desired := partyAssignments(entry.Parties)
	stillPinned := map[string]struct{}{}
	for _, key := range entry.Keys() {
		stillPinned[key] = struct{}{}
	}
	for key, party := range current {
		if _, keep := stillPinned[key]; !keep {
			continue
		}
		want, grouped := desired[key]
		if !grouped {
			return fmt.Errorf("%s already groups %s under %q; skillctl connect will not ungroup it",
				entry.Name, attest.Fingerprint(key), party)
		}
		if want != party {
			return fmt.Errorf("%s already groups %s under %q; Axela returned %q",
				entry.Name, attest.Fingerprint(key), party, want)
		}
	}
	return nil
}

func partyAssignments(parties map[string][]string) map[string]string {
	if len(parties) == 0 {
		return nil
	}
	assignments := make(map[string]string, len(parties))
	for party, keys := range parties {
		for _, key := range keys {
			assignments[key] = party
		}
	}
	return assignments
}

func saveBootstrapSubscriptionsFile(subscriptions []Subscription) error {
	sort.Slice(subscriptions, func(i, j int) bool { return subscriptions[i].Name < subscriptions[j].Name })
	body, err := json.MarshalIndent(subscriptions, "", "  ")
	if err != nil {
		return err
	}
	return writeOwnerOnlyFileAtomically(subscriptionsPath(), append(body, '\n'))
}

func parseConnectKey(encoded string) (ed25519.PublicKey, error) {
	key, err := attest.ParsePublicKey([]byte(encoded))
	if err != nil {
		return nil, fmt.Errorf("Axela returned an unusable public key: %w", err)
	}
	return key, nil
}

func configureReporting(machine, ingestURL string) error {
	config, err := report.LoadConfig(reportConfigPath())
	if err != nil {
		return err
	}
	if config.Machine == "" {
		config.Machine = machine
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = reportTimeoutSeconds
	}
	config.Timeout = time.Duration(config.TimeoutSeconds) * time.Second

	found := false
	for index := range config.Destinations {
		destination := &config.Destinations[index]
		if destination.Kind == "webhook" && destination.URL == ingestURL {
			configureWebhookDestination(destination)
			found = true
			break
		}
	}
	if !found {
		destination := report.Destination{Kind: "webhook", URL: ingestURL}
		configureWebhookDestination(&destination)
		config.Destinations = append(config.Destinations, destination)
	}
	return saveHomeJSON(reportConfigPath(), config)
}

func configureWebhookDestination(destination *report.Destination) {
	destination.BearerTokenFile = connectCredentialsPath()
	destination.ReceiptFile = connectStatusPath()
	destination.Payloads = []string{"events", "checks"}
	destination.HealthyChecks = true
	if len(destination.Headers) == 0 {
		return
	}
	for key := range destination.Headers {
		if strings.EqualFold(key, "Authorization") {
			delete(destination.Headers, key)
		}
	}
	if len(destination.Headers) == 0 {
		destination.Headers = nil
	}
}

func installManagedHooks() ([]string, []string) {
	detected := detectManagedAgents()
	if len(detected) == 0 {
		return nil, []string{"no managed Claude Code or Codex home was found, so no session hook was installed"}
	}

	var installed []string
	var attention []string
	for _, known := range detected {
		added, err := applyClaudeHooks(known.HookConfigPath(), known.Hooks(executablePath()))
		if err != nil {
			attention = append(attention, fmt.Sprintf("%s hook could not be installed: %v", known.Name, err))
			continue
		}
		if len(added) > 0 || hookInstalled(known) {
			installed = append(installed, known.Name)
		}
	}
	return installed, attention
}

func detectManagedAgents() []agent {
	var detected []agent
	for _, known := range agents {
		if !known.Managed || known.Hooks == nil {
			continue
		}
		if info, err := os.Stat(known.Home()); err == nil && info.IsDir() {
			detected = append(detected, known)
			continue
		}
		if info, err := os.Stat(known.HookConfigPath()); err == nil && !info.IsDir() {
			detected = append(detected, known)
		}
	}
	return detected
}

func appendUniqueConnectNote(notes []string, note string) []string {
	if containsString(notes, note) {
		return notes
	}
	return append(notes, note)
}

func preferredManagedAgent(found []agent) (agent, bool) {
	for _, preferred := range []string{"claude", "codex"} {
		for _, known := range found {
			if known.Name == preferred {
				return known, true
			}
		}
	}
	if len(found) == 0 {
		return agent{}, false
	}
	return found[0], true
}

func hookInstalled(known agent) bool {
	raw, err := os.ReadFile(known.HookConfigPath())
	if err != nil {
		return false
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return false
	}
	hooks, _ := document["hooks"].(map[string]any)
	groups, _ := hooks["SessionStart"].([]any)
	needle := "hook session-start"
	if known.Name == "codex" {
		needle = "hook session-start --agent codex"
	}
	return hookAlreadyPresent(groups, needle)
}

func pollUntilConnected(base string, pending *pendingConnect, wait time.Duration) (*enrollment.Connection, bool, error) {
	deadline := connectNow().Add(wait)
	first := true
	for {
		connection, keepWaiting, err := pollConnectStatus(base, pending)
		if err != nil || !keepWaiting {
			return connection, keepWaiting, err
		}
		if !first && connectNow().After(deadline) {
			return nil, true, nil
		}
		if first {
			first = false
			if wait == 0 {
				return nil, true, nil
			}
		}
		if connectNow().After(deadline) {
			return nil, true, nil
		}
		connectSleep(time.Second)
	}
}

func pollConnectStatus(base string, pending *pendingConnect) (*enrollment.Connection, bool, error) {
	body, err := json.Marshal(pending.Envelope)
	if err != nil {
		return nil, false, err
	}
	request, err := http.NewRequest(http.MethodPost, base+"/v1/connect/status", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+pending.Token)

	response, err := connectHTTPClient(connectTimeout).Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()

	message, err := io.ReadAll(io.LimitReader(response.Body, connectMaxResponseBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("Axela returned an unreadable connection response: %w", err)
	}
	if len(message) > connectMaxResponseBytes {
		return nil, false, fmt.Errorf("Axela returned too much connection data")
	}
	switch response.StatusCode {
	case http.StatusAccepted:
		return nil, true, nil
	case http.StatusOK:
		var connection enrollment.Connection
		if err := json.Unmarshal(message, &connection); err != nil {
			return nil, false, fmt.Errorf("Axela approved this computer but returned unreadable setup data")
		}
		return &connection, false, nil
	case http.StatusForbidden:
		text := strings.TrimSpace(string(message))
		if text == "" {
			text = "this organisation is not accepting new connections right now"
		}
		return nil, false, connectBlocked{message: text}
	default:
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, false, fmt.Errorf("Axela tried to redirect the connection check; use the final HTTPS service URL")
		}
		text := strings.TrimSpace(string(message))
		if text == "" {
			text = response.Status
		}
		return nil, false, fmt.Errorf("Axela could not confirm this connection: %s", text)
	}
}

func connectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validateConnection(base string, pending *pendingConnect, connection *enrollment.Connection) error {
	if connection == nil {
		return fmt.Errorf("Axela returned no connection details")
	}
	if connection.Organisation == "" || connection.MachineKeyID == "" {
		return fmt.Errorf("Axela returned incomplete connection details")
	}
	if pending == nil || pending.MachineKeyID == "" {
		return fmt.Errorf("this machine has no pending connection proof to bind the approval to")
	}
	if connection.MachineKeyID != pending.MachineKeyID {
		return fmt.Errorf("Axela approved another machine key; run skillctl connect again")
	}
	ingestURL, err := canonicalServiceURL(connection.IngestURL, "ingest URL")
	if err != nil {
		return err
	}
	dashboardURL, err := canonicalServiceURL(connection.DashboardURL, "dashboard URL")
	if err != nil {
		return err
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return err
	}
	for field, raw := range map[string]string{"ingest URL": ingestURL, "dashboard URL": dashboardURL} {
		parsed, err := url.Parse(raw)
		if err != nil {
			return err
		}
		if parsed.Scheme != baseURL.Scheme || parsed.Host != baseURL.Host {
			return fmt.Errorf("Axela returned a %s on another origin", field)
		}
	}
	return nil
}

func canonicalServiceURL(raw, field string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("Axela returned an unusable %s", field)
	}
	loopback := parsed.Hostname() == "localhost"
	if ip := net.ParseIP(parsed.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return "", fmt.Errorf("Axela returned an insecure %s", field)
	}
	return parsed.String(), nil
}

func approvalURL(base string, envelope *attest.Envelope) (string, error) {
	body, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return base + "/connect?request=" + base64.RawURLEncoding.EncodeToString(body), nil
}

func ensurePendingConnect(base, machine string, current *pendingConnect, now time.Time) (*pendingConnect, bool, error) {
	label := connectMachine(machine)
	if current != nil {
		if current.Audience != base {
			return nil, false, fmt.Errorf("a connection to %s is already in progress; use a separate SKILLTRUST_HOME for another service", current.Audience)
		}
		if machine == "" {
			label = current.Machine
		}
		private, err := attest.LoadPrivateKey(defaultSigningKey())
		if err != nil {
			return nil, false, err
		}
		if attest.KeyID(private.Public().(ed25519.PublicKey)) != current.MachineKeyID {
			return nil, false, fmt.Errorf("the signing key changed while approval was pending; restore the original key before reconnecting")
		}
		if current.Machine == label {
			return current, false, nil
		}
	}
	return createPendingConnect(base, label, now)
}

func createPendingConnect(base, machine string, now time.Time) (*pendingConnect, bool, error) {
	key, public, _, err := ensureSigningKey(gitIdentity())
	if err != nil {
		return nil, false, err
	}

	token, err := randomHex(32)
	if err != nil {
		return nil, false, err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return nil, false, err
	}
	request := enrollment.Request{
		Audience:    base,
		Nonce:       nonce,
		Machine:     machine,
		TokenDigest: secretDigest(token),
		IssuedAt:    now,
		ExpiresAt:   now.Add(enrollment.Lifetime),
	}
	envelope, err := enrollment.Sign(request, key)
	if err != nil {
		return nil, false, err
	}
	created := &pendingConnect{
		Version:      connectPendingVersion,
		Audience:     base,
		Machine:      machine,
		MachineKeyID: attest.KeyID(public),
		Token:        token,
		Envelope:     envelope,
		RequestedAt:  now,
	}
	if err := saveHomeJSON(pendingConnectPath(), created); err != nil {
		return nil, false, err
	}
	return created, true, nil
}

func connectMachine(explicit string) string {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "this-computer"
}

func loadPendingConnect(now time.Time) (*pendingConnect, error) {
	raw, err := os.ReadFile(pendingConnectPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pending pendingConnect
	if err := json.Unmarshal(raw, &pending); err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", pendingConnectPath(), err)
	}
	if pending.Version != connectPendingVersion || pending.Envelope == nil {
		return nil, fmt.Errorf("%s is not a usable pending connection", pendingConnectPath())
	}
	if _, err := hex.DecodeString(pending.Token); err != nil || len(pending.Token) != 64 {
		return nil, fmt.Errorf("%s holds an unusable local credential", pendingConnectPath())
	}
	request, keyID, expired, err := readPendingRequest(pending.Envelope, now)
	if err != nil {
		return nil, fmt.Errorf("%s is not a usable pending connection: %w", pendingConnectPath(), err)
	}
	if pending.Audience != "" && pending.Audience != request.Audience {
		return nil, fmt.Errorf("%s belongs to another service", pendingConnectPath())
	}
	if pending.Machine != "" && pending.Machine != request.Machine {
		return nil, fmt.Errorf("%s belongs to another machine label", pendingConnectPath())
	}
	if request.TokenDigest != secretDigest(pending.Token) {
		return nil, fmt.Errorf("%s holds a token that does not match its signed request", pendingConnectPath())
	}
	pending.Audience = request.Audience
	pending.Machine = request.Machine
	pending.MachineKeyID = keyID
	pending.Expired = expired
	if pending.RequestedAt.IsZero() {
		pending.RequestedAt = request.IssuedAt
	}
	return &pending, nil
}

func readPendingRequest(
	envelope *attest.Envelope, now time.Time,
) (*enrollment.Request, string, bool, error) {
	if envelope == nil {
		return nil, "", false, fmt.Errorf("missing connection request")
	}
	rawEnvelope, err := json.Marshal(envelope)
	if err != nil || len(rawEnvelope) > enrollment.MaxBytes {
		return nil, "", false, fmt.Errorf("connection request is too large")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, "", false, fmt.Errorf("connection request is unreadable")
	}
	var request enrollment.Request
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, "", false, fmt.Errorf("connection request is unreadable")
	}
	key, err := attest.ParsePublicKey([]byte(request.PublicKey))
	if err != nil {
		return nil, "", false, fmt.Errorf("connection request has no usable public key")
	}
	if _, _, err := attest.VerifyPayload(envelope, enrollment.PayloadType, attest.NewTrustedKeys(key)); err != nil {
		return nil, "", false, err
	}
	base, err := enrollment.BaseURL(request.Audience)
	if err != nil || request.Audience != base || request.Version != 1 {
		return nil, "", false, fmt.Errorf("connection request belongs to another service; run skillctl connect again")
	}
	if request.IssuedAt.After(now.Add(time.Minute)) ||
		request.ExpiresAt.Sub(request.IssuedAt) > enrollment.Lifetime ||
		!request.ExpiresAt.After(request.IssuedAt) {
		return nil, "", false, fmt.Errorf("connection request expired; run skillctl connect again")
	}
	for _, value := range []string{request.Nonce, request.TokenDigest} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
			return nil, "", false, fmt.Errorf("connection request has an invalid identifier")
		}
	}
	if len(request.Machine) == 0 || len(request.Machine) > 100 || strings.ContainsAny(request.Machine, "\r\n\x00") {
		return nil, "", false, fmt.Errorf("give this computer a short name")
	}
	return &request, attest.KeyID(key), !request.ExpiresAt.After(now), nil
}

func loadSavedConnect() (*savedConnect, error) {
	raw, err := os.ReadFile(connectStatePath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var saved savedConnect
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", connectStatePath(), err)
	}
	return &saved, nil
}

// Resuming needs the saved bootstrap and the machine's private credential, not
// the short-lived browser proof. A new current check still verifies admission.
func resumeSavedConnect(base string, current *savedConnect) (*pendingConnect, *enrollment.Connection, error) {
	if current == nil || current.Version != connectRecordVersion {
		return nil, nil, fmt.Errorf("the saved connection format is not supported")
	}
	if current.Audience != base {
		return nil, nil, fmt.Errorf("this computer is already connected to %s; use a separate SKILLTRUST_HOME to connect to another service", current.Audience)
	}
	private, err := attest.LoadPrivateKey(defaultSigningKey())
	if err != nil {
		return nil, nil, err
	}
	public := private.Public().(ed25519.PublicKey)
	if attest.KeyID(public) != current.MachineKeyID {
		return nil, nil, fmt.Errorf("the local signing key no longer matches this computer's connection; restore the original key before reconnecting")
	}
	raw, err := os.ReadFile(connectCredentialsPath())
	if err != nil {
		return nil, nil, fmt.Errorf("cannot resume without the local reporting credential: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return nil, nil, fmt.Errorf("the local reporting credential is not usable")
	}
	pending := &pendingConnect{Version: connectPendingVersion, Audience: base,
		Machine: current.Machine, MachineKeyID: current.MachineKeyID, Token: token, Resuming: true}
	connection := &enrollment.Connection{Organisation: current.Organisation,
		MachineKeyID: current.MachineKeyID, IngestURL: current.IngestURL, DashboardURL: current.DashboardURL,
		PublisherKeys: current.PublisherKeys, NotaryKeys: current.NotaryKeys, Catalogs: current.Catalogs}
	if err := validateConnection(base, pending, connection); err != nil {
		return nil, nil, err
	}
	return pending, connection, nil
}

func resolveConnectBase(raw string, pending *pendingConnect, current *savedConnect) (string, error) {
	switch {
	case raw != "":
		return enrollment.BaseURL(raw)
	case current != nil && current.Audience != "":
		return enrollment.BaseURL(current.Audience)
	case pending != nil && pending.Audience != "":
		return enrollment.BaseURL(pending.Audience)
	default:
		return connectDefaultBaseURL, nil
	}
}

func pendingConnectPath() string     { return homePath("connect-pending.json") }
func connectStatePath() string       { return homePath("connection.json") }
func connectCredentialsPath() string { return homePath("reporting.token") }
func connectStatusPath() string      { return homePath("reporting.status.json") }

func saveHomeJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeOwnerOnlyFileAtomically(path, append(body, '\n'))
}

func writeOwnerOnlyText(path, contents string) error {
	return writeOwnerOnlyFileAtomically(path, []byte(contents))
}

func writeOwnerOnlyFileAtomically(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
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

func randomHex(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func secretDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func openBrowser(raw string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", raw).Start()
	case "linux":
		return exec.Command("xdg-open", raw).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", raw).Start()
	default:
		return fmt.Errorf("open this URL in a browser: %s", raw)
	}
}
