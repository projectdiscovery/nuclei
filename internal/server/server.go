package server

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alitto/pond"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/server/proxy"
	"github.com/projectdiscovery/nuclei/v3/internal/server/scope"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/utils/env"
)

// DASTServer is a server that performs execution of fuzzing templates
// on user input passed to the API.
type DASTServer struct {
	httpServer   *http.Server
	options      *Options
	tasksPool    *pond.WorkerPool
	deduplicator *requestDeduplicator
	scopeManager *scope.Manager
	proxy        *proxy.Proxy
	startTime    time.Time

	// metrics
	endpointsInQueue     atomic.Int64
	endpointsBeingTested atomic.Int64

	nucleiExecutor *nucleiExecutor
}

// Options contains the configuration options for the server.
type Options struct {
	// Address is the address to bind the server to
	Address string
	// Token is the token to use for authentication (optional)
	Token string
	// Templates is the list of templates to use for fuzzing
	Templates []string
	// Verbose is a flag that controls verbose output
	Verbose bool

	// ProxyAddress enables the intercepting proxy front-end on this address
	ProxyAddress string
	// ProxyCADir is the directory holding the proxy interception CA
	ProxyCADir string
	// ProxyUsername and ProxyPassword gate the intercepting proxy with basic
	// authentication. Mandatory when ProxyAddress is not a loopback address.
	ProxyUsername string
	ProxyPassword string

	// Scope fields for fuzzer
	InScope  []string
	OutScope []string

	OutputWriter output.Writer

	NucleiExecutorOptions *NucleiExecutorOptions
}

// New creates a new instance of the DAST server.
func New(options *Options) (*DASTServer, error) {
	// If the user has specified no templates, use the default ones
	// for DAST only.
	if len(options.Templates) == 0 {
		options.Templates = []string{"dast/"}
	}
	// Disable bulk mode and single threaded execution
	// by auto adjusting in case of default values
	if options.NucleiExecutorOptions.Options.BulkSize == 25 && options.NucleiExecutorOptions.Options.TemplateThreads == 25 {
		options.NucleiExecutorOptions.Options.BulkSize = 1
		options.NucleiExecutorOptions.Options.TemplateThreads = 1
	}
	maxWorkers := env.GetEnvOrDefault[int]("FUZZ_MAX_WORKERS", 1)
	bufferSize := env.GetEnvOrDefault[int]("FUZZ_BUFFER_SIZE", 10000)

	server := &DASTServer{
		options:      options,
		tasksPool:    pond.New(maxWorkers, bufferSize),
		deduplicator: newRequestDeduplicator(),
		startTime:    time.Now(),
	}
	server.setupHandlers(false)

	executor, err := newNucleiExecutor(options.NucleiExecutorOptions)
	if err != nil {
		return nil, err
	}
	server.nucleiExecutor = executor

	scopeManager, err := scope.NewManager(
		options.InScope,
		options.OutScope,
	)
	if err != nil {
		return nil, err
	}
	server.scopeManager = scopeManager

	if options.ProxyAddress != "" {
		if err := server.setupProxy(); err != nil {
			return nil, err
		}
	}

	var builder strings.Builder
	gologger.Debug().Msgf("Using %d parallel tasks with %d buffer", maxWorkers, bufferSize)
	if options.Token != "" {
		builder.WriteString(" (with token)")
	}
	gologger.Info().Msgf("DAST Server API: %s", server.buildURL("/fuzz"))
	gologger.Info().Msgf("DAST Server Stats URL: %s", server.buildURL("/stats"))

	return server, nil
}

// setupProxy wires the intercepting proxy front-end into the same queue the
// HTTP API feeds.
func (s *DASTServer) setupProxy() error {
	interceptingProxy, err := proxy.New(&proxy.Options{
		Address:   s.options.ProxyAddress,
		CADir:     s.options.ProxyCADir,
		Username:  s.options.ProxyUsername,
		Password:  s.options.ProxyPassword,
		Verbose:   s.options.Verbose,
		Intercept: s.shouldIntercept,
		Submit:    s.Submit,
	})
	if err != nil {
		return err
	}
	s.proxy = interceptingProxy

	gologger.Info().Msgf("DAST Proxy: http://%s", s.options.ProxyAddress)
	gologger.Info().Msgf("DAST Proxy CA certificate: %s (install it to intercept https)", interceptingProxy.CertPath())
	gologger.Info().Msgf("DAST Proxy CA download: %s", s.buildURL("/ca"))
	// Info, not Warning: gologger orders LevelWarning above LevelInfo, so
	// warnings are filtered out at default verbosity and these two notices
	// describe what interception does to the user's traffic.
	gologger.Info().Msgf("DAST Proxy: intercepted https is re-originated by nuclei, target certificates are not verified")
	if len(s.options.InScope) == 0 && len(s.options.OutScope) == 0 {
		gologger.Info().Msgf("DAST Proxy: no scope set, every proxied https host will be decrypted (narrow it with -fuzz-scope / -fuzz-out-scope)")
	}
	return nil
}

// shouldIntercept decides whether a CONNECT tunnel is decrypted. Only an
// explicit out-of-scope match leaves a host encrypted, because in-scope
// patterns may carry a path that a CONNECT host can never match against.
func (s *DASTServer) shouldIntercept(hostPort string) bool {
	host := hostPort
	// Only the default port is dropped, so the synthesised URL has the same
	// shape as the request URLs these rules are applied to once a request has
	// actually been captured.
	if parsedHost, port, err := net.SplitHostPort(hostPort); err == nil && port == "443" {
		host = parsedHost
	}
	return !s.scopeManager.IsExplicitlyOutOfScope(&url.URL{Scheme: "https", Host: host, Path: "/"})
}

func NewStatsServer(fuzzStatsDB *stats.Tracker) (*DASTServer, error) {
	server := &DASTServer{
		options: &Options{},
		nucleiExecutor: &nucleiExecutor{
			executorOpts: &protocols.ExecutorOptions{
				FuzzStatsDB: fuzzStatsDB,
			},
		},
	}
	server.setupHandlers(true)
	gologger.Info().Msgf("Stats UI URL: %s", server.buildURL("/stats"))

	return server, nil
}

func (s *DASTServer) Close() {
	if s.proxy != nil {
		if err := s.proxy.Close(); err != nil {
			gologger.Warning().Msgf("Could not close dast proxy: %s", err)
		}
	}
	if s.nucleiExecutor != nil {
		s.nucleiExecutor.Close()
	}
	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.tasksPool != nil {
		s.tasksPool.StopAndWaitFor(1 * time.Minute)
	}
}

func (s *DASTServer) buildURL(endpoint string) string {
	values := make(url.Values)
	opts := s.optionsOrDefault()
	if opts.Token != "" {
		values.Set("token", opts.Token)
	}

	// Use url.URL struct to safely construct the URL
	u := &url.URL{
		Scheme:   "http",
		Host:     opts.Address,
		Path:     endpoint,
		RawQuery: values.Encode(),
	}
	return u.String()
}

func (s *DASTServer) optionsOrDefault() *Options {
	if s.options != nil {
		return s.options
	}
	return &Options{}
}

func (s *DASTServer) setupHandlers(onlyStats bool) {
	mux := http.NewServeMux()
	// POST /fuzz - Queue a request for fuzzing
	if !onlyStats {
		mux.HandleFunc("POST /fuzz", s.handleRequest)
	}
	mux.HandleFunc("GET /stats", s.handleStats)
	mux.HandleFunc("GET /stats.json", s.handleStatsJSON)
	if !onlyStats && s.optionsOrDefault().ProxyAddress != "" {
		mux.HandleFunc("GET /ca", s.handleProxyCA)
	}

	handler := http.Handler(mux)
	opts := s.optionsOrDefault()
	if opts.Token != "" {
		handler = s.tokenAuthMiddleware(handler)
	}
	handler = corsMiddleware(handler)
	if opts.Verbose {
		handler = requestLoggerMiddleware(handler)
	}
	handler = recoverMiddleware(handler)

	s.httpServer = &http.Server{Handler: handler}
}

func (s *DASTServer) Start() error {
	if s.httpServer == nil {
		s.setupHandlers(false)
	}
	s.httpServer.Addr = s.optionsOrDefault().Address

	if s.proxy == nil {
		return s.serveAPI()
	}

	// Both front-ends feed the same queue; whichever fails first ends the run.
	errs := make(chan error, 2)
	go func() { errs <- s.serveAPI() }()
	go func() { errs <- s.proxy.Start() }()
	return <-errs
}

func (s *DASTServer) serveAPI() error {
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handleProxyCA serves the interception CA certificate so it can be installed.
// Only the certificate is ever served, never the private key.
func (s *DASTServer) handleProxyCA(w http.ResponseWriter, _ *http.Request) {
	if s.proxy == nil {
		writeServerJSON(w, http.StatusNotFound, map[string]string{"error": "proxy is not enabled"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="nuclei-dast-proxy-ca.pem"`)
	_, _ = w.Write(s.proxy.CertPEM())
}

// PostRequestsHandlerRequest is the request body for the /fuzz POST handler.
type PostRequestsHandlerRequest struct {
	RawHTTP string `json:"raw_http"`
	URL     string `json:"url"`
}

func (s *DASTServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	var req PostRequestsHandlerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Printf("Error binding request: %s\n", err)
		writeServerJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Validate the request
	if req.RawHTTP == "" || req.URL == "" {
		fmt.Printf("Missing required fields\n")
		writeServerJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required fields"})
		return
	}

	if !s.Submit(req.RawHTTP, req.URL) {
		writeServerJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scan queue is full"})
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Submit queues a captured request for fuzzing and reports whether it was
// accepted. It never blocks: a saturated scanner must not stall the live
// traffic flowing through the proxy, so excess requests are dropped instead.
func (s *DASTServer) Submit(rawHTTP, targetURL string) bool {
	req := PostRequestsHandlerRequest{RawHTTP: rawHTTP, URL: targetURL}

	s.endpointsInQueue.Add(1)
	if !s.tasksPool.TrySubmit(func() { s.consumeTaskRequest(req) }) {
		s.endpointsInQueue.Add(-1)
		return false
	}
	return true
}

type StatsResponse struct {
	DASTServerInfo            DASTServerInfo     `json:"dast_server_info"`
	DASTScanStatistics        DASTScanStatistics `json:"dast_scan_statistics"`
	DASTScanStatusStatistics  map[string]int64   `json:"dast_scan_status_statistics"`
	DASTScanSeverityBreakdown map[string]int64   `json:"dast_scan_severity_breakdown"`
	DASTScanErrorStatistics   map[string]int64   `json:"dast_scan_error_statistics"`
	DASTScanStartTime         time.Time          `json:"dast_scan_start_time"`
}

type DASTServerInfo struct {
	NucleiVersion         string `json:"nuclei_version"`
	NucleiTemplateVersion string `json:"nuclei_template_version"`
	NucleiDastServerAPI   string `json:"nuclei_dast_server_api"`
	ServerAuthEnabled     bool   `json:"sever_auth_enabled"`
	NucleiDastProxyAddr   string `json:"nuclei_dast_proxy_address,omitempty"`
	ProxyAuthEnabled      bool   `json:"proxy_auth_enabled"`
}

type DASTScanStatistics struct {
	EndpointsInQueue      int64 `json:"endpoints_in_queue"`
	EndpointsBeingTested  int64 `json:"endpoints_being_tested"`
	TotalTemplatesLoaded  int64 `json:"total_dast_templates_loaded"`
	TotalTemplatesTested  int64 `json:"total_dast_templates_tested"`
	TotalMatchedResults   int64 `json:"total_matched_results"`
	TotalComponentsTested int64 `json:"total_components_tested"`
	TotalEndpointsTested  int64 `json:"total_endpoints_tested"`
	TotalFuzzedRequests   int64 `json:"total_fuzzed_requests"`
	TotalErroredRequests  int64 `json:"total_errored_requests"`

	// Proxy counters, populated only in proxy mode. A rising drop count means
	// the scanner cannot keep up with the proxied traffic.
	ProxyRequestsIntercepted  int64 `json:"proxy_requests_intercepted"`
	ProxyTunnelsPassedThrough int64 `json:"proxy_tunnels_passed_through"`
	ProxyRequestsDropped      int64 `json:"proxy_requests_dropped"`
}

func (s *DASTServer) getStats() (StatsResponse, error) {
	cfg := config.DefaultConfig

	resp := StatsResponse{
		DASTServerInfo: DASTServerInfo{
			NucleiVersion:         config.Version,
			NucleiTemplateVersion: cfg.TemplateVersion,
			NucleiDastServerAPI:   s.buildURL("/fuzz"),
			ServerAuthEnabled:     s.options.Token != "",
			NucleiDastProxyAddr:   s.options.ProxyAddress,
			ProxyAuthEnabled:      s.options.ProxyUsername != "",
		},
		DASTScanStartTime: s.startTime,
		DASTScanStatistics: DASTScanStatistics{
			EndpointsInQueue:     s.endpointsInQueue.Load(),
			EndpointsBeingTested: s.endpointsBeingTested.Load(),
			TotalTemplatesLoaded: int64(len(s.nucleiExecutor.store.Templates())),
		},
	}
	if s.proxy != nil {
		proxyStats := s.proxy.Stats()
		resp.DASTScanStatistics.ProxyRequestsIntercepted = proxyStats.Intercepted
		resp.DASTScanStatistics.ProxyTunnelsPassedThrough = proxyStats.TunnelsPassedThrough
		resp.DASTScanStatistics.ProxyRequestsDropped = proxyStats.Dropped
	}
	if s.nucleiExecutor.executorOpts.FuzzStatsDB != nil {
		fuzzStats := s.nucleiExecutor.executorOpts.FuzzStatsDB.GetStats()
		resp.DASTScanSeverityBreakdown = fuzzStats.SeverityCounts
		resp.DASTScanStatusStatistics = fuzzStats.StatusCodes
		resp.DASTScanStatistics.TotalMatchedResults = fuzzStats.TotalMatchedResults
		resp.DASTScanStatistics.TotalComponentsTested = fuzzStats.TotalComponentsTested
		resp.DASTScanStatistics.TotalEndpointsTested = fuzzStats.TotalEndpointsTested
		resp.DASTScanStatistics.TotalFuzzedRequests = fuzzStats.TotalFuzzedRequests
		resp.DASTScanStatistics.TotalTemplatesTested = fuzzStats.TotalTemplatesTested
		resp.DASTScanStatistics.TotalErroredRequests = fuzzStats.TotalErroredRequests
		resp.DASTScanErrorStatistics = fuzzStats.ErrorGroupedStats
	}
	return resp, nil
}

//go:embed templates/index.html
var indexTemplate string

func (s *DASTServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats, err := s.getStats()
	if err != nil {
		writeServerJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	tmpl, err := template.New("index").Parse(indexTemplate)
	if err != nil {
		writeServerJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tmpl.Execute(w, stats); err != nil {
		writeServerJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func (s *DASTServer) handleStatsJSON(w http.ResponseWriter, _ *http.Request) {
	resp, err := s.getStats()
	if err != nil {
		writeServerJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeServerJSONPretty(w, http.StatusOK, resp)
}

func (s *DASTServer) tokenAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			writeServerJSON(w, http.StatusBadRequest, map[string]string{"message": "missing key in the query string"})
			return
		}
		if token != s.optionsOrDefault().Token {
			writeServerJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	const allowMethods = "GET,HEAD,PUT,PATCH,POST,DELETE"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Add("Vary", "Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		if r.Method == http.MethodOptions {
			if origin != "" {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				w.Header().Set("Access-Control-Allow-Methods", allowMethods)
				if headers := r.Header.Get("Access-Control-Request-Headers"); headers != "" {
					w.Header().Set("Access-Control-Allow-Headers", headers)
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats" || r.URL.Path == "/stats.json" {
			next.ServeHTTP(w, r)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		fmt.Printf("%s %s %d %s\n", r.Method, r.URL.RequestURI(), recorder.statusCode, time.Since(start))
	})
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func writeServerJSON(w http.ResponseWriter, statusCode int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func writeServerJSONPretty(w http.ResponseWriter, statusCode int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(statusCode)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}
