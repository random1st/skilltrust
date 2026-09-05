package notary

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/source"
	"github.com/random1st/skilltrust/report"
)

// Handler is the notary's HTTP surface: publish with a token, fetch without one.
//
// The upload limit is the client's download limit on purpose. Accepting a catalog larger
// than source.MaxIndexBytes would mean storing something every subscribed machine then
// refuses, which is a publish that reports success and delivers nothing.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/catalogs/{org}/{marketplace}", s.handlePublish)
	mux.HandleFunc("GET /v1/catalogs/{org}/{marketplace}", s.handleFetch)
	mux.HandleFunc("POST /v1/events/{org}", s.handleIngest)
	mux.HandleFunc("GET /v1/events/{org}", s.handleEvents)
	mux.HandleFunc("GET /v1/checks/{org}", s.handleChecks)
	mux.HandleFunc("GET /ui/{org}", s.handleDashboard)
	mux.HandleFunc("GET /{$}", s.handleLanding)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /favicon.svg", s.handleFavicon)
	mux.HandleFunc("GET /notary.pub", s.handleNotaryKey)
	mux.HandleFunc("GET /v1/keys", s.handleKeySet)
	return mux
}

// handleNotaryKey serves the countersigning public key as PEM, named the way the
// subscribe instructions name it, so `curl -O` produces the file they mention.
//
// Every consumer instruction ends "--key notary.pub --threshold 2", and until this route
// existed nothing served that file: the instruction was not executable by a stranger.
// Serving the key from the notary itself is trust-on-first-use — someone who can forge
// this response can hand out a key they hold. That is inherent in any first fetch, is
// mitigated by TLS, and is why the fingerprint is worth publishing somewhere that is not
// this server. What the pin then guarantees is that the notary cannot change out from
// under a machine after it subscribed.
func (s *Service) handleNotaryKey(w http.ResponseWriter, r *http.Request) {
	pem, err := attest.EncodePublicKey(s.keys[0].Public().(ed25519.PublicKey))
	if err != nil {
		http.Error(w, "the key could not be encoded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-Key-Id", s.KeyID())
	w.Write(pem)
}

// handleKeySet serves the signed announcement of every current countersigning key.
//
// Unlike /notary.pub this is not trust-on-first-use: the envelope is signed by the
// current keys, so a machine that already pins one verifies the announcement against
// that pin and learns the incoming key over a chain of trust rather than over a hope
// about TLS. This is the read side of rotation; `skillctl refresh` and sync are the
// write side on the consumer's disk.
func (s *Service) handleKeySet(w http.ResponseWriter, r *http.Request) {
	envelope, err := s.KeySet(time.Now().UTC())
	if err != nil {
		http.Error(w, "the key set could not be signed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(envelope); err != nil {
		return
	}
}

// bearer extracts the token, empty when absent — which never matches, because an empty
// configured token disables the role rather than accepting an empty header.
func bearer(r *http.Request) string {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token
}

func (s *Service) handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEventBytes+1))
	if err != nil || len(body) > MaxEventBytes {
		http.Error(w, "the event could not be read, or is too large", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	token := bearer(r)
	if payloadType(body) == report.CheckPayloadType {
		org, trusted, err := s.authorizeCheckIngest(r.PathValue("org"), token, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		receipt, err := s.AcceptCheck(org, body, trusted, now)
		if err != nil {
			if errors.Is(err, ErrRefused) {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			http.Error(w, "the check could not be stored", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"receipt": receipt})
		return
	}

	if s.checkAdmission != nil {
		org, trusted, err := s.checkAdmission.AuthorizeCheck(r.PathValue("org"), token, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if _, err := s.AcceptVerifiedEvent(org, body, trusted, now); err != nil {
			if errors.Is(err, ErrRefused) {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			http.Error(w, "the event could not be stored", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	org, authErr := s.AuthorizeIngest(r.PathValue("org"), token)
	if authErr != nil {
		http.Error(w, authErr.Error(), http.StatusUnauthorized)
		return
	}
	if _, err := s.AcceptEvent(org, body); err != nil {
		if errors.Is(err, ErrRefused) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, "the event could not be stored", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Service) authorizeCheckIngest(orgName, token string, now time.Time) (Org, *attest.TrustedKeys, error) {
	if s.checkAdmission != nil {
		return s.checkAdmission.AuthorizeCheck(orgName, token, now)
	}
	org, authErr := s.AuthorizeIngest(orgName, token)
	if authErr != nil {
		return Org{}, nil, authErr
	}
	return org, org.Machines, nil
}

func (s *Service) handleEvents(w http.ResponseWriter, r *http.Request) {
	org, err := s.AuthorizeAdmin(r.PathValue("org"), bearer(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	events, err := s.ServeEvents(org)
	if err != nil {
		http.Error(w, "events could not be read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"events": events})
}

func (s *Service) handleChecks(w http.ResponseWriter, r *http.Request) {
	org, err := s.AuthorizeAdmin(r.PathValue("org"), bearer(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	checks, err := s.ServeChecks(org)
	if err != nil {
		http.Error(w, "checks could not be read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"checks": checks})
}

func (s *Service) handlePublish(w http.ResponseWriter, r *http.Request) {
	// Two dots make a JWT; anything else is a static token. A static token containing
	// dots is not a case worth supporting — it would be indistinguishable on purpose.
	token := bearer(r)
	var org Org
	var where Provenance
	var err error
	if strings.Count(token, ".") == 2 {
		org, where, err = s.AuthorizeOIDC(r.PathValue("org"), token, time.Now().UTC())
	} else {
		org, err = s.Authorize(r.PathValue("org"), token)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, source.MaxIndexBytes+1))
	if err != nil {
		http.Error(w, "the catalog could not be read", http.StatusBadRequest)
		return
	}
	if len(body) > source.MaxIndexBytes {
		http.Error(w, "the catalog is larger than subscribed machines will accept",
			http.StatusRequestEntityTooLarge)
		return
	}

	countersigned, err := s.AcceptFrom(r.Context(), org, r.PathValue("marketplace"), body, where)
	switch {
	case errors.Is(err, ErrRollback):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, ErrRefused):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	case err != nil:
		http.Error(w, "the catalog could not be stored", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(countersigned)
}

func (s *Service) handleFetch(w http.ResponseWriter, r *http.Request) {
	body, err := s.Serve(r.PathValue("org"), r.PathValue("marketplace"))
	if errors.Is(err, ErrAbsent) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "the catalog could not be read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func payloadType(body []byte) string {
	envelope := extractEnvelope(body)
	if envelope == nil {
		return ""
	}
	var parsed attest.Envelope
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return ""
	}
	return parsed.PayloadType
}
