package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const maxBody = 4 << 20

// Handler serves the decision and bundle endpoints.
func (g *Gate) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if g.Active() == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no active bundle"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/decide", func(w http.ResponseWriter, r *http.Request) {
		b := g.Active()
		if b == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no active bundle"})
			return
		}
		var in struct {
			Request map[string]string `json:"request"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		d, err := b.Eval.Decide(in.Request)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"effect": d.Effect, "rule": d.Rule, "bundle": b.Digest})
	})

	mux.HandleFunc("GET /v1/bundle", func(w http.ResponseWriter, _ *http.Request) {
		b := g.Active()
		if b == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no active bundle"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"name": b.Name, "digest": b.Digest})
	})

	mux.HandleFunc("PUT /v1/bundle", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
			return
		}
		b, err := g.Propose(r.Context(), body, r.Header.Get("X-Proofgate-Approval"))
		var rej *Rejection
		switch {
		case errors.As(err, &rej):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": rej.Reason, "evidence": rej.Report})
		case err != nil:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusOK, map[string]string{"name": b.Name, "digest": b.Digest})
		}
	})
	return mux
}

func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
