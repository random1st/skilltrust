package notary

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/report"
)

// The console is a reader. It renders what the notary already stores and verifies it the
// same way the CLI does; it cannot revoke, sign or publish, because the keys that could
// are deliberately not on this server. A browser compromise therefore reads a dashboard —
// it does not publish a catalog.

//go:embed templates
var templates embed.FS

var pages = template.Must(template.ParseFS(templates, "templates/*.html"))

// Dashboard is everything one organisation's page shows.
type Dashboard struct {
	Brand        string
	Org          string
	Now          time.Time
	Marketplaces []MarketplaceView
	Machines     []MachineView
	// ActiveMachines counts machines with a current signed check inside its freshness
	// window, whether that check is healthy or needs attention.
	ActiveMachines int
	Events         []EventView
	// Unverified counts stored events no configured machine key signed. Shown as a
	// number rather than as rows: unverifiable prose next to verified evidence invites
	// reading the wrong one.
	Unverified int
	// NoMachineKeys is true when the organisation pins no machine keys at all, which is a
	// different situation from an event signed by a key that is not among them and used to
	// print the same sentence as one.
	//
	// The two need different words because they need different actions. An unpinned key is
	// something to investigate: somebody's machine is filing reports under an identity this
	// organisation never registered. No keys at all is a setup step nobody has done, and
	// the reader is not looking at evidence of anything — they are looking at every report
	// they have ever filed, uncounted, with no hint that registering a key is what turns
	// the number into a fleet.
	NoMachineKeys bool
	// Attention is what a person came here to find out, in the words they would use. A
	// dashboard of three tables asks the reader to work out whether anything is wrong by
	// scanning six columns of zeros, which is a question the page can answer itself.
	// Empty means nothing needs looking at, and that is worth saying out loud too.
	Attention []string
	// CurrentStateWarnings report when the live roster or current checks could not be read,
	// so the fleet view keeps whatever history it has without claiming that the current state
	// is healthy.
	CurrentStateWarnings []string
	// AdaptedNote qualifies the all-clear. "Every machine found what you published" is
	// false on a fleet with adopted copies, and a headline that overclaims once is a
	// headline nobody trusts about the machines that matter. Empty when nothing is adopted.
	AdaptedNote string
	// Session is true when the viewer arrived through the login form rather than
	// HTTP Basic; it decides whether a sign-out button makes sense.
	Session bool
}

type MarketplaceView struct {
	Name       string
	Sequence   int64
	ValidUntil time.Time
	Expired    bool
	Skills     int
	Revoked    int
	Signers    []SignerView
}

type SignerView struct {
	Fingerprint string
	// Role is "publisher", "notary" or "unknown" — who this signature belongs to, as far
	// as this server's own configuration can say.
	Role string
}

type MachineView struct {
	Name            string
	Signer          string
	Status          string
	Last            time.Time
	FreshUntil      time.Time
	Checked         int
	Changed         int
	Unapproved      int
	Errors          int
	Complete        bool
	Scopes          []string
	Restored        int
	Revoked         int
	Unverifiable    int
	CatalogUnusable int
	// Adapted counts plugins someone at that machine deliberately keeps modified —
	// distinct plugins, not events. A machine files the same adoption every session, and
	// counting events read as 250 modified copies where there was one, a year old. Not an
	// incident, and shown anyway: it is the one case where a machine knowingly runs bytes
	// no publisher signed, and an organisation that cannot see it does not know what its
	// fleet is running.
	Adapted int
	// SkillsChanged counts skills that no longer match the approval they were given —
	// distinct skills, not events, for the same reason Adapted counts copies. A machine
	// files the same drift every session until somebody acts on it, and counting events
	// would report one edited skill as fifty.
	//
	// Kept apart from Restored because the two say different things. A restored plugin is
	// back to what the publisher signed; a changed skill is still changed, because nothing
	// outside a marketplace has a published copy to put back.
	SkillsChanged int
}

// Unchecked is how many times this machine could not answer the question at all — an
// unreadable plugin or a marketplace it could not verify. They are one column because they
// are one thing to a reader: something went unchecked, and "we could not check" is the only
// state that must never be mistaken for "nothing had changed".
func (m MachineView) Unchecked() int { return m.Unverifiable + m.CatalogUnusable }

func (m MachineView) ScopeSummary() string {
	if len(m.Scopes) == 0 {
		return "no current check"
	}
	return strings.Join(m.Scopes, ", ")
}

type EventView struct {
	At        time.Time
	Machine   string
	Summary   string
	Kind      string
	Admission string
}

// BuildDashboard assembles the page from stored state, tolerating partial damage: one
// unreadable marketplace must not blank the whole console, and is instead absent — the
// events section still names what its machines reported about it.
func (s *Service) BuildDashboard(org Org, now time.Time) Dashboard {
	dashboard := Dashboard{Brand: s.brand, Org: org.Name, Now: now}

	for _, name := range s.storage.Marketplaces(org.Name) {
		body, err := s.Serve(org.Name, name)
		if err != nil {
			continue
		}
		var envelope attest.Envelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			continue
		}
		// Open, not Verify: the console shows an expired catalog with its expiry in red
		// rather than pretending it does not exist. Freshness is a client-side refusal;
		// here staleness is exactly the finding.
		snapshot, _, err := catalog.Open(&envelope, org.Publishers)
		if err != nil {
			continue
		}
		view := MarketplaceView{
			Name: name, Sequence: snapshot.Sequence,
			ValidUntil: snapshot.ValidUntil, Expired: !now.Before(snapshot.ValidUntil),
			Skills: len(snapshot.Skills), Revoked: len(snapshot.Revoked),
		}
		ours := s.keyIDSet()
		for _, signature := range envelope.Signatures {
			role := "unknown"
			if _, mine := ours[signature.KeyID]; mine {
				role = "notary"
			} else if _, pinned := org.Publishers.Lookup(signature.KeyID); pinned {
				role = "publisher"
			}
			view.Signers = append(view.Signers, SignerView{
				Fingerprint: attest.Fingerprint(signature.KeyID), Role: role,
			})
		}
		dashboard.Marketplaces = append(dashboard.Marketplaces, view)
	}

	type machineState struct {
		view           MachineView
		registered     bool
		disabled       bool
		freshUnknown   bool
		hasCheck       bool
		stale          bool
		statusUnknown  bool
		needsAttention bool
	}
	machines := map[string]*machineState{}
	ensure := func(key, name, signer string) *machineState {
		if key == "" {
			key = name
		}
		row := machines[key]
		if row == nil {
			row = &machineState{view: MachineView{Name: name}}
			machines[key] = row
		}
		if row.view.Name == "" && name != "" {
			row.view.Name = name
		}
		if signer != "" {
			row.view.Signer = attest.Fingerprint(signer)
		}
		return row
	}
	liveRosterUnavailable := false
	if registry, ok := s.directory.(MachineRegistry); ok {
		if registered, err := registry.RegisteredMachines(org.Name); err == nil {
			for _, machine := range registered {
				key := machine.Signer
				if key == "" {
					key = machine.Name
				}
				row := ensure(key, machine.Name, machine.Signer)
				row.registered = true
				row.disabled = machine.Disabled
			}
		} else {
			liveRosterUnavailable = true
			dashboard.CurrentStateWarnings = append(dashboard.CurrentStateWarnings,
				"The current list of computers is unavailable. Refresh this page to try again.")
		}
	}
	if checks, err := s.ServeChecks(org); err == nil {
		for _, record := range checks {
			key := record.Receipt.Signer
			if key == "" {
				key = record.Result.Machine
			}
			row := ensure(key, record.Result.Machine, record.Receipt.Signer)
			row.hasCheck = true
			if len(row.view.Scopes) == 0 {
				row.view.Complete = true
			}
			row.view.Complete = row.view.Complete && record.Result.Complete
			row.view.Scopes = append(row.view.Scopes, record.Result.Scope)
			row.view.Checked += record.Result.Checked
			row.view.Changed += record.Result.Changed
			row.view.Unapproved += record.Result.Unapproved
			row.view.Errors += record.Result.Errors
			if record.Result.CheckedAt.After(row.view.Last) {
				row.view.Last = record.Result.CheckedAt
			}
			switch {
			case record.Result.FreshUntil.IsZero():
				row.freshUnknown = true
				row.view.FreshUntil = time.Time{}
			case !row.freshUnknown &&
				(row.view.FreshUntil.IsZero() || record.Result.FreshUntil.Before(row.view.FreshUntil)):
				row.view.FreshUntil = record.Result.FreshUntil
			}
			if !record.Result.Complete || record.Result.Changed > 0 || record.Result.Unapproved > 0 ||
				record.Result.Errors > 0 || record.Result.FreshUntil.IsZero() {
				row.needsAttention = true
			}
			if record.Result.FreshUntil.IsZero() || !now.Before(record.Result.FreshUntil) {
				row.stale = true
			}
			if !record.Result.HealthyAt(now) {
				row.needsAttention = true
			}
			if !row.registered {
				if liveRosterUnavailable {
					row.statusUnknown = true
					continue
				}
				if org.Machines == nil {
					row.disabled = true
					continue
				}
				if _, ok := org.Machines.Lookup(record.Receipt.Signer); ok {
					row.registered = true
				} else {
					row.disabled = true
				}
			}
		}
	} else {
		dashboard.CurrentStateWarnings = append(dashboard.CurrentStateWarnings,
			"The latest checks are unavailable. Refresh this page to try again.")
	}

	stored, err := s.ServeEvents(org)
	if err == nil {
		var historical *attest.TrustedKeys
		if registry, ok := s.directory.(HistoricalMachineRegistry); ok {
			historical, _ = registry.HistoricalMachineKeys(org.Name)
		}
		type signedEvent struct {
			event     report.Event
			signer    string
			admission string
		}
		// One adoption, one row. The same adopted plugin is reported every session, and a
		// table of one reason repeated fifty times informs nobody about anything else.
		type adoptionKey struct{ signer, marketplace, plugin string }
		adoptions := map[adoptionKey]signedEvent{}
		type skillKey struct{ signer, skill string }
		drifted := map[skillKey]signedEvent{}
		for _, raw := range stored {
			admission := ""
			event, signer, found, err := s.verifyAcceptedEvent(org.Name, raw)
			if err != nil {
				dashboard.Unverified++
				continue
			}
			if !found {
				var envelope attest.Envelope
				if err := json.Unmarshal(raw, &envelope); err != nil {
					dashboard.Unverified++
					continue
				}
				verified := false
				if org.Machines != nil {
					event, signer, err = report.Verify(&envelope, org.Machines)
					if err == nil {
						verified = true
					}
				}
				if !verified && historical != nil && historical.Len() > 0 {
					event, signer, err = report.Verify(&envelope, historical)
					if err == nil {
						verified = true
					}
				}
				if !verified {
					dashboard.Unverified++
					continue
				}
				admission = "UNKNOWN"
			}

			key := signer
			if key == "" {
				key = event.Machine
			}
			row := ensure(key, event.Machine, signer)
			activeSigner := false
			if org.Machines != nil {
				_, activeSigner = org.Machines.Lookup(signer)
			}
			switch {
			case activeSigner:
				if liveRosterUnavailable {
					row.statusUnknown = true
				} else {
					row.registered = true
				}
			case found || admission == "UNKNOWN":
				if liveRosterUnavailable {
					row.statusUnknown = true
				} else {
					row.disabled = true
				}
			}
			if event.Kind == report.KindSkillChanged {
				key := skillKey{signer, event.Skill}
				if previous, seen := drifted[key]; !seen || event.At.After(previous.event.At) {
					drifted[key] = signedEvent{event: *event, signer: signer, admission: admission}
				}
				continue
			}
			if event.Kind == report.KindAdapted {
				key := adoptionKey{signer, event.Marketplace, event.Plugin}
				if previous, seen := adoptions[key]; !seen || event.At.After(previous.event.At) {
					adoptions[key] = signedEvent{event: *event, signer: signer, admission: admission}
				}
				continue
			}
			switch event.Kind {
			case report.KindRestored:
				row.view.Restored++
			case report.KindRevoked:
				row.view.Revoked++
			case report.KindUnverifiable:
				row.view.Unverifiable++
			case report.KindCatalogUnusable:
				row.view.CatalogUnusable++
			}
			dashboard.Events = append(dashboard.Events, EventView{
				At: event.At, Machine: event.Machine,
				Summary: event.Summary(), Kind: string(event.Kind), Admission: admission,
			})
		}
		for key, event := range drifted {
			row := ensure(key.signer, event.event.Machine, event.signer)
			row.view.SkillsChanged++
			dashboard.Events = append(dashboard.Events, EventView{
				At: event.event.At, Machine: event.event.Machine,
				Summary: event.event.Summary(), Kind: string(event.event.Kind), Admission: event.admission,
			})
		}
		for key, event := range adoptions {
			row := ensure(key.signer, event.event.Machine, event.signer)
			row.view.Adapted++
			dashboard.Events = append(dashboard.Events, EventView{
				At: event.event.At, Machine: event.event.Machine,
				Summary: event.event.Summary(), Kind: string(event.event.Kind), Admission: event.admission,
			})
		}
	}

	for _, row := range machines {
		sort.Strings(row.view.Scopes)
		switch {
		case row.disabled:
			row.view.Status = "Disabled"
		case !row.hasCheck:
			row.view.Status = "Pending"
		case row.stale:
			row.view.Status = "Stale"
		case row.needsAttention:
			row.view.Status = "Needs attention"
			dashboard.ActiveMachines++
		case row.statusUnknown:
			row.view.Status = "Unknown"
		default:
			row.view.Status = "Checked"
			dashboard.ActiveMachines++
		}
		dashboard.Machines = append(dashboard.Machines, row.view)
	}

	sort.Slice(dashboard.Machines, func(i, j int) bool {
		return dashboard.Machines[i].Name < dashboard.Machines[j].Name
	})
	sort.Slice(dashboard.Events, func(i, j int) bool {
		return dashboard.Events[i].At.After(dashboard.Events[j].At)
	})
	if len(dashboard.Events) > 50 {
		dashboard.Events = dashboard.Events[:50]
	}
	sort.Slice(dashboard.Marketplaces, func(i, j int) bool {
		return dashboard.Marketplaces[i].Name < dashboard.Marketplaces[j].Name
	})
	// Only worth saying once something has arrived. An organisation with no machines and no
	// events is not misconfigured, it is new, and greeting it with a warning about a
	// situation it is not in teaches people to ignore the panel.
	dashboard.NoMachineKeys = org.Machines == nil && dashboard.Unverified > 0
	dashboard.Attention = whatNeedsLookingAt(dashboard)

	adaptedPlugins, adaptedMachines := 0, 0
	for _, view := range dashboard.Machines {
		if view.Adapted > 0 {
			adaptedMachines++
			adaptedPlugins += view.Adapted
		}
	}
	switch {
	case adaptedPlugins == 1:
		dashboard.AdaptedNote = "1 plugin is a modified copy its owner chose to keep; " +
			"everything else matches what you published."
	case adaptedPlugins > 1:
		dashboard.AdaptedNote = fmt.Sprintf(
			"%s across %s are modified copies their owners chose to keep; everything else "+
				"matches what you published.",
			plural(adaptedPlugins, "plugin"), plural(adaptedMachines, "machine"))
	}
	return dashboard
}

// whatNeedsLookingAt turns the tables into the sentences a person would say. Each line
// names the thing and how many, because "3 machines" is actionable and "something is
// wrong" is not.
func whatNeedsLookingAt(dashboard Dashboard) []string {
	var lines []string

	// First, because every other line on this panel is derived from machines and there are
	// none: with no key registered, no report can be attributed and the tables below are
	// empty for a reason that has nothing to do with the fleet being healthy.
	if dashboard.NoMachineKeys {
		lines = append(lines, fmt.Sprintf(
			"%s arrived but this organisation registers no machine keys, so none of them "+
				"could be attributed — register the key each machine signs with",
			plural(dashboard.Unverified, "report")))
	}

	for _, view := range dashboard.Marketplaces {
		if view.Expired {
			lines = append(lines, fmt.Sprintf(
				"%s expired on %s, so machines following it have stopped accepting it — publish again",
				view.Name, view.ValidUntil.Format("2 January")))
		}
	}

	pending, checked, attention, stale, disabled := 0, 0, 0, 0, 0
	for _, machine := range dashboard.Machines {
		switch machine.Status {
		case "Pending":
			pending++
		case "Checked":
			checked++
		case "Needs attention":
			attention++
		case "Stale":
			stale++
		case "Disabled":
			disabled++
		}
	}
	if attention > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s needs attention in its latest signed check", plural(attention, "machine")))
	}
	if pending > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s has not filed a signed current check yet", plural(pending, "machine")))
	}
	if stale > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s is stale and needs a fresh check", plural(stale, "machine")))
	}
	if disabled > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s is disabled and kept only for history", plural(disabled, "machine")))
	}
	if dashboard.Unverified > 0 && !dashboard.NoMachineKeys {
		lines = append(lines, fmt.Sprintf(
			"%s stored event(s) are not signed by any machine key this notary currently trusts",
			plural(dashboard.Unverified, "event")))
	}
	return lines
}

// plural keeps a count reading as English. "1 machines" is the kind of thing that makes a
// reader stop trusting the rest of the number.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// sessionCookie carries "org:admin-token" — exactly the credential HTTP Basic resends on
// every request, in a jar the browser manages better: HttpOnly, SameSite, and clearable
// by a sign-out button. There is deliberately no server-side session to store or fixate.
const sessionCookie = "notary_session"

// page is what the public templates render: no organisation data beyond the name the
// viewer already typed.
type page struct {
	Brand   string
	Org     string
	Session bool
	Error   string
	Prefill string
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
	}
}

// secureRequest reports whether the viewer reached us over TLS, directly or through the
// reverse proxy that terminates it; the session cookie is marked Secure exactly then, so
// a loopback deployment without TLS still works.
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *Service) handleLanding(w http.ResponseWriter, r *http.Request) {
	render(w, "landing.html", page{Brand: s.brand})
}

func (s *Service) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	render(w, "login.html", page{Brand: s.brand, Prefill: r.URL.Query().Get("org")})
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	orgName := r.FormValue("org")
	token := r.FormValue("token")
	// The same non-oracle as the API: a wrong token and an unknown organisation are one
	// answer, and the comparison inside is constant-time.
	if _, err := s.AuthorizeAdmin(orgName, token); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		render(w, "login.html", page{Brand: s.brand, Prefill: orgName, Error: err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: orgName + ":" + token,
		Path: "/", MaxAge: 12 * 60 * 60,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secureRequest(r),
	})
	http.Redirect(w, r, "/ui/"+orgName, http.StatusSeeOther)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secureRequest(r),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleDashboard accepts either HTTP Basic (the admin token as the password — curl and
// the tests use this) or the session cookie the login form set. A browser with neither
// is sent to the form rather than shown a bare 401.
func (s *Service) handleDashboard(w http.ResponseWriter, r *http.Request) {
	orgName := r.PathValue("org")
	session := false
	_, token, haveBasic := r.BasicAuth()
	if !haveBasic {
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			if cookieOrg, cookieToken, ok := strings.Cut(cookie.Value, ":"); ok && cookieOrg == orgName {
				token, session = cookieToken, true
			}
		}
	}
	if token == "" {
		http.Redirect(w, r, "/login?org="+url.QueryEscape(orgName), http.StatusSeeOther)
		return
	}

	org, err := s.AuthorizeAdmin(orgName, token)
	if err != nil {
		if session {
			// The cookie is stale — the token rotated, most likely. Back to the form.
			s.handleLogout(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="notary", charset="UTF-8"`)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	s.RenderDashboard(w, org, session)
}

// RenderDashboard writes the console for an organisation the caller has already
// authorized. A deployment that authenticates its operators some other way — an identity
// provider, an authenticating proxy — reaches the same page through here rather than
// reimplementing the template, and the notary keeps no opinion about how the person at
// the other end proved who they are.
func (s *Service) RenderDashboard(w http.ResponseWriter, org Org, session bool) {
	dashboard := s.BuildDashboard(org, time.Now().UTC())
	dashboard.Session = session
	render(w, "dashboard.html", dashboard)
}

// A diamond seal: the mark two signatures close.
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="20" fill="#2563eb"/><path d="M50 18 82 50 50 82 18 50Z" fill="none" stroke="#fff" stroke-width="8"/></svg>`

func (s *Service) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(faviconSVG))
}
