package httpapi

import (
	"net/http"
	"time"

	"github.com/projectdiscovery/gologger"
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
	token  string
	config *types.Options
}

// New creates a new instance of Server.
func New(addr string, config *types.Options) *Server {
	return &Server{
		addr:   addr,
		token:  config.HttpApiToken,
		config: config,
	}
}

// Start initializes the server and its routes, then starts listening on the specified address.
//
// A dedicated ServeMux is used (rather than http.DefaultServeMux via
// http.HandleFunc/http.ListenAndServe) so this experimental endpoint never
// accidentally exposes handlers registered on the default mux by other
// packages (e.g. net/http/pprof, which is blank-imported for the separate,
// opt-in -enable-pprof server).
func (s *Server) Start() error {
	if s.token == "" {
		gologger.Warning().Msgf("http-api-endpoint is running without a token (-http-api-token); anyone able to reach %s can read and change scan settings", s.addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/concurrency", s.handleConcurrency)

	var handler http.Handler = mux
	if s.token != "" {
		handler = s.tokenAuthMiddleware(handler)
	}

	server := &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		return err
	}
	return nil
}

// tokenAuthMiddleware requires a matching ?token= query parameter on every
// request when a token has been configured.
func (s *Server) tokenAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" || token != s.token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// GetSettings handles GET requests and returns the current concurrency settings
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

// UpdateSettings handles PUT requests to update the concurrency settings
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
		s.config.JsConcurrency = newSettings.JavascriptConcurrency // no-op on speed change
	}

	w.WriteHeader(http.StatusOK)
}
