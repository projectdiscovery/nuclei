package httpapi

import (
	"net/http"
	"sync/atomic"
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
	addr        string
	config      *types.Options
	httpServer  *http.Server
	jsConcStore atomic.Int32
}

// New creates a new instance of Server.
func New(addr string, config *types.Options) *Server {
	s := &Server{
		addr:   addr,
		config: config,
	}
	s.jsConcStore.Store(int32(compiler.PoolingJsVmConcurrency))
	return s
}

// Start initializes the server and its routes, then starts listening on the specified address.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/concurrency", s.handleConcurrency)

	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// handleConcurrency routes the request based on its method to the appropriate handler.
func (s *Server) handleConcurrency(w http.ResponseWriter, r *http.Request) {
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
		JavascriptConcurrency: int(s.jsConcStore.Load()),
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
		s.jsConcStore.Store(int32(newSettings.JavascriptConcurrency))
		compiler.PoolingJsVmConcurrency = newSettings.JavascriptConcurrency
		s.config.JsConcurrency = newSettings.JavascriptConcurrency
	}

	w.WriteHeader(http.StatusOK)
}
