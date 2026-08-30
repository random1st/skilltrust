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
	// ActiveMachines counts machines whose latest verified report is within thirty days
	// of Now. It is the fleet-size number a per-machine plan meters, computed from the
	// same signed events the table shows — so an operator can always see which machines
	// make up the count, and a machine that stops reporting ages out on its own.
	ActiveMachines int
	Events         []EventView
	// Unverified counts stored events no configured machine key signed. Shown as a
	// number rather than as rows: unverifiable prose next to verified evidence invites
	// reading the wrong one.
	Unverified int
	// Attention is what a person came here to find out, in the words they would use. A
	// dashboard of three tables asks the reader to work out whether anything is wrong by
	// scanning six columns of zeros, which is a question the page can answer itself.
	// Empty means nothing needs looking at, and that is worth saying out loud too.
	Attention []string
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
	Last            time.Time
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
}

// Unchecked is how many times this machine could not answer the question at all — an
// unreadable plugin or a marketplace it could not verify. They are one column because they
// are one thing to a reader: something went unchecked, and "we could not check" is the only
// state that must never be mistaken for "nothing had changed".
func (m MachineView) Unchecked() int { return m.Unverifiable + m.CatalogUnusable }

type EventView struct {
	At      time.Time
	Machine string
	Summary string
	Kind    string
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

	stored, err := s.ServeEvents(org)
	if err == nil {
		machines := map[string]*MachineView{}
		// One adoption, one row. The same adopted plugin is reported every session, and a
		// table of one reason repeated fifty times informs nobody about anything else.
		type adoptionKey struct{ machine, marketplace, plugin string }
		adoptions := map[adoptionKey]report.Event{}
		for _, raw := range stored {
			var envelope attest.Envelope
			if err := json.Unmarshal(raw, &envelope); err != nil {
				dashboard.Unverified++
				continue
			}
			if org.Machines == nil {
				dashboard.Unverified++
				continue
			}
			event, _, err := report.Verify(&envelope, org.Machines)
			if err != nil {
				dashboard.Unverified++
				continue
			}

			view := machines[event.Machine]
			if view == nil {
				view = &MachineView{Name: event.Machine}
				machines[event.Machine] = view
			}
			if event.At.After(view.Last) {
				view.Last = event.At
			}
			if event.Kind == report.KindAdapted {
				key := adoptionKey{event.Machine, event.Marketplace, event.Plugin}
				if previous, seen := adoptions[key]; !seen || event.At.After(previous.At) {
					adoptions[key] = *event
				}
				continue
			}
			switch event.Kind {
			case report.KindRestored:
				view.Restored++
			case report.KindRevoked:
				view.Revoked++
			case report.KindUnverifiable:
				view.Unverifiable++
			case report.KindCatalogUnusable:
				view.CatalogUnusable++
			}
			dashboard.Events = append(dashboard.Events, EventView{
				At: event.At, Machine: event.Machine,
				Summary: event.Summary(), Kind: string(event.Kind),
			})
		}
		for key, event := range adoptions {
			machines[key.machine].Adapted++
			dashboard.Events = append(dashboard.Events, EventView{
				At: event.At, Machine: event.Machine,
				Summary: event.Summary(), Kind: string(event.Kind),
			})
		}
		for _, view := range machines {
			dashboard.Machines = append(dashboard.Machines, *view)
			if view.Last.After(dashboard.Now.AddDate(0, 0, -30)) {
				dashboard.ActiveMachines++
			}
		}
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

	for _, view := range dashboard.Marketplaces {
		if view.Expired {
			lines = append(lines, fmt.Sprintf(
				"%s expired on %s, so machines following it have stopped accepting it — publish again",
				view.Name, view.ValidUntil.Format("2 January")))
		}
	}

	restored, revoked, unreadable, stale := 0, 0, 0, 0
	for _, machine := range dashboard.Machines {
		if machine.Restored > 0 {
			restored++
		}
		if machine.Revoked > 0 {
			revoked++
		}
		if machine.Unchecked() > 0 {
			unreadable++
		}
		if machine.Last.Before(dashboard.Now.AddDate(0, 0, -30)) {
			stale++
		}
	}
	// Revocation first: it is the only line that means a machine ran into something you
	// withdrew, and burying it under three counters is how it gets read last.
	if revoked > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s found a skill you revoked and refused to load it", plural(revoked, "machine")))
	}
	if restored > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s had a skill changed and put the published copy back", plural(restored, "machine")))
	}
	if unreadable > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s could not check something, so it went unchecked", plural(unreadable, "machine")))
	}
	if stale > 0 {
		lines = append(lines, fmt.Sprintf(
			"%s has not reported in over a month", plural(stale, "machine")))
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
