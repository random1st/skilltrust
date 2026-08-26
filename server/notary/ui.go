package notary

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/internal/attest"
	"github.com/random1st/skilltrust/internal/catalog"
	"github.com/random1st/skilltrust/internal/report"
)

// The console is a reader. It renders what the notary already stores and verifies it the
// same way the CLI does; it cannot revoke, sign or publish, because the keys that could
// are deliberately not on this server. A browser compromise therefore reads a dashboard —
// it does not publish a catalog.

//go:embed templates/dashboard.html
var templates embed.FS

var dashboardTemplate = template.Must(template.ParseFS(templates, "templates/dashboard.html"))

// Dashboard is everything one organisation's page shows.
type Dashboard struct {
	Org          string
	Now          time.Time
	Marketplaces []MarketplaceView
	Machines     []MachineView
	Events       []EventView
	// Unverified counts stored events no configured machine key signed. Shown as a
	// number rather than as rows: unverifiable prose next to verified evidence invites
	// reading the wrong one.
	Unverified int
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
}

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
	dashboard := Dashboard{Org: org.Name, Now: now}

	for _, name := range s.marketplaceNames(org.Name) {
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
		for _, signature := range envelope.Signatures {
			role := "unknown"
			if signature.KeyID == s.KeyID() {
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
		for _, view := range machines {
			dashboard.Machines = append(dashboard.Machines, *view)
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
	return dashboard
}

// marketplaceNames lists what has been published for an organisation: the directories
// beside "events" that hold a catalog.
func (s *Service) marketplaceNames(orgName string) []string {
	entries, err := os.ReadDir(filepath.Join(s.dataDir, "orgs", orgName))
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "events" || !name.MatchString(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

// handleDashboard serves the console under HTTP Basic auth, the admin token as the
// password. Basic fits a read-only page: the browser handles the prompt, there is no
// session to fixate and no state-changing endpoint for CSRF to reach.
func (s *Service) handleDashboard(w http.ResponseWriter, r *http.Request) {
	_, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="skilltrust", charset="UTF-8"`)
		http.Error(w, "the admin token is the password", http.StatusUnauthorized)
		return
	}
	// The same non-oracle as the API: a wrong token and an unknown organisation are one
	// answer, and the comparison inside is constant-time.
	org, err := s.AuthorizeAdmin(r.PathValue("org"), password)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="skilltrust", charset="UTF-8"`)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, s.BuildDashboard(org, time.Now().UTC())); err != nil {
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
	}
}
