package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

type Concurrency struct {
	BulkSize              int    `json:"bulk_size"`
	Threads               int    `json:"threads"`
	RateLimit             int    `json:"rate_limit"`
	RateLimitDuration     string `json:"rate_limit_duration"`
	PayloadConcurrency    int    `json:"payload_concurrency"`
	ProbeConcurrency      int    `json:"probe_concurrency"`
	JavascriptConcurrency int    `json:"javascript_concurrency"`
}

// Server represents the HTTP server that handles the concurrency settings endpoints.
type Server struct {
	addr   string
	config *types.Options
	// token is a random Bearer token that must be presented by callers.
	token string
}

// New creates a new instance of Server.  A random 32-byte hex Bearer token is
// generated and stored; the caller should log it so operators can authenticate.
func New(addr string, config *types.Options) *Server {
	return &Server{
		addr:   addr,
		config: config,
		token:  randomToken(),
	}
}

// Token returns the Bearer token that callers must supply in an
// "Authorization: Bearer <token>" header.
func (s *Server) Token() string {
	return s.token
}

// randomToken generates a 32-byte (64 hex char) cryptographically random token.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("httpapi: could not generate random token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// authenticate rejects requests whose Authorization header does not carry the
// server's Bearer token.  Returns true when the request is authorized.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if s.token == "" {
		return true // token-less mode: explicitly disabled
	}
	auth := r.Header.Get("Authorization")
	want := "Bearer " + s.token
	if !strings.EqualFold(auth, want) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// Start initializes the server and its routes, then starts listening on the specified address.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/concurrency", s.handleConcurrency)
	if err := http.ListenAndServe(s.addr, mux); err != nil {
		return err
	}
	return nil
}

// handleConcurrency routes the request based on its method to the appropriate handler.
func (s *Server) handleConcurrency(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getSettings(w, r)
	case http.MethodPut:
		s.updateSettings(w, r)
	default:
		http.Error(w, "Unsupported HTTP method", http.StatusMethodNotAllowed)
	}
}

// getSettings handles GET requests and returns the current concurrency settings.
func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	concurrencySettings := Concurrency{
		BulkSize:              s.config.BulkSize,
		Threads:               s.config.TemplateThreads,
		RateLimit:             s.config.RateLimit,
		RateLimitDuration:     s.config.RateLimitDuration.String(),
		PayloadConcurrency:    s.config.PayloadConcurrency,
		ProbeConcurrency:      s.config.ProbeConcurrency,
		JavascriptConcurrency: compiler.PoolingJsVmConcurrency,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(concurrencySettings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// updateSettings handles PUT requests to update the concurrency settings.
func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var newSettings Concurrency
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if newSettings.RateLimitDuration != "" {
		if duration, err := time.ParseDuration(newSettings.RateLimitDuration); err == nil {
			s.config.RateLimitDuration = duration
		} else {
			http.Error(w, "Invalid duration format", http.StatusBadRequest)
			return
		}
	}
	if newSettings.BulkSize > 0 {
		s.config.BulkSize = newSettings.BulkSize
	}
	if newSettings.Threads > 0 {
		s.config.TemplateThreads = newSettings.Threads
	}
	if newSettings.RateLimit > 0 {
		s.config.RateLimit = newSettings.RateLimit
	}
	if newSettings.PayloadConcurrency > 0 {
		s.config.PayloadConcurrency = newSettings.PayloadConcurrency
	}
	if newSettings.ProbeConcurrency > 0 {
		s.config.ProbeConcurrency = newSettings.ProbeConcurrency
	}
	if newSettings.JavascriptConcurrency > 0 {
		compiler.PoolingJsVmConcurrency = newSettings.JavascriptConcurrency
		s.config.JsConcurrency = newSettings.JavascriptConcurrency
	}

	w.WriteHeader(http.StatusOK)
}
