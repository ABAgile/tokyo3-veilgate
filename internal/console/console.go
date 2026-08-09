// Package console serves Veilgate's read-only flow examination UI and API.
package console

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/veilgate/internal/flow"
)

//go:embed static/*
var assets embed.FS

// Handler returns a console handler backed by store. When username and
// password are both non-empty, every route except /healthz uses HTTP Basic.
func Handler(store *flow.Store, username, password string) (http.Handler, error) {
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("console assets: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	mux.HandleFunc("GET /api/v1/flows", func(w http.ResponseWriter, r *http.Request) {
		filter, err := parseFilter(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page, err := store.ListPageSummary(r.Context(), filter)
		if err != nil {
			http.Error(w, "flow store unavailable", http.StatusInternalServerError)
			return
		}
		for i := range page.Flows {
			page.Flows[i] = flowSummary(page.Flows[i])
		}
		for i := range page.SessionParents {
			page.SessionParents[i] = flowSummary(page.SessionParents[i])
		}
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("GET /api/v1/flows/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid flow id", http.StatusBadRequest)
			return
		}
		item, ok, err := store.Get(r.Context(), id)
		if err != nil {
			http.Error(w, "flow store unavailable", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "flow not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, item)
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		filter, err := parseFilter(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Pagination bounds apply only to history, never to the live tail.
		filter.BeforeID = 0
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		events, cancel := store.Subscribe()
		defer cancel()
		_, _ = fmt.Fprint(w, ": connected\n\n")
		flusher.Flush()
		keepalive := time.NewTicker(20 * time.Second)
		defer keepalive.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case item := <-events:
				if !filter.Matches(item) {
					continue
				}
				payload, err := json.Marshal(flowSummary(item))
				if err != nil {
					return
				}
				if _, err := fmt.Fprintf(w, "id: %d\nevent: flow\ndata: %s\n\n", item.ID, payload); err != nil {
					return
				}
				flusher.Flush()
			case <-keepalive.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := assets.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "console unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	secured := securityHeaders(mux)
	if username != "" && password != "" {
		secured = basicAuth(secured, username, password)
	}
	return secured, nil
}

func flowSummary(item flow.Flow) flow.Flow {
	item.SecretNames = nil
	item.ResponseSecretNames = nil
	item.PolicyTrace = nil
	item.Capture = flow.TrafficCapture{}
	return item
}

func parseFilter(r *http.Request) (flow.Filter, error) {
	query := r.URL.Query()
	filter := flow.Filter{
		Client:   strings.TrimSpace(query.Get("client")),
		Host:     strings.ToLower(strings.TrimSpace(query.Get("host"))),
		Decision: strings.ToLower(strings.TrimSpace(query.Get("decision"))),
		Mode:     strings.ToLower(strings.TrimSpace(query.Get("mode"))),
	}
	for name, value := range map[string]string{"client": filter.Client, "host": filter.Host, "mode": filter.Mode} {
		if len(value) > 253 {
			return flow.Filter{}, fmt.Errorf("%s filter is too long", name)
		}
	}
	if filter.Decision != "" && filter.Decision != "allowed" && filter.Decision != "denied" {
		return flow.Filter{}, errors.New("decision filter must be allowed or denied")
	}
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 10000 {
			return flow.Filter{}, errors.New("limit must be between 1 and 10000")
		}
		filter.Limit = limit
	}
	if raw := query.Get("before_id"); raw != "" {
		beforeID, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || beforeID < 1 {
			return flow.Filter{}, errors.New("before_id must be a positive integer")
		}
		filter.BeforeID = beforeID
	}
	return filter, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func basicAuth(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		gotUser, gotPassword, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(username)) == 1
		passwordOK := subtle.ConstantTimeCompare([]byte(gotPassword), []byte(password)) == 1
		if !ok || !userOK || !passwordOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="veilgate console", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
