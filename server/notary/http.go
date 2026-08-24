package notary

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/random1st/skilltrust/internal/source"
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
	return mux
}

// bearer extracts the token, empty when absent — which never matches, because an empty
// configured token disables the role rather than accepting an empty header.
func bearer(r *http.Request) string {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token
}

func (s *Service) handleIngest(w http.ResponseWriter, r *http.Request) {
	org, err := s.AuthorizeIngest(r.PathValue("org"), bearer(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEventBytes+1))
	if err != nil || len(body) > MaxEventBytes {
		http.Error(w, "the event could not be read, or is too large", http.StatusBadRequest)
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

func (s *Service) handlePublish(w http.ResponseWriter, r *http.Request) {
	// Two dots make a JWT; anything else is a static token. A static token containing
	// dots is not a case worth supporting — it would be indistinguishable on purpose.
	token := bearer(r)
	var org Org
	var err error
	if strings.Count(token, ".") == 2 {
		org, err = s.AuthorizeOIDC(r.PathValue("org"), token, time.Now().UTC())
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

	countersigned, err := s.Accept(org, r.PathValue("marketplace"), body)
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
