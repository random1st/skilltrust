package notary

import (
	"errors"
	"io"
	"net/http"
	"strings"

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
	return mux
}

func (s *Service) handlePublish(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "a bearer token is required", http.StatusUnauthorized)
		return
	}
	org, err := s.Authorize(r.PathValue("org"), token)
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
