package server

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alitto/pond"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/gologger"
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
	echo         *echo.Echo
	options      *Options
	tasksPool    *pond.WorkerPool
	deduplicator *requestDeduplicator
	scopeManager *scope.Manager
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

	var builder strings.Builder
	gologger.Debug().Msgf("Using %d parallel tasks with %d buffer", maxWorkers, bufferSize)
	if options.Token != "" {
		builder.WriteString(" (with token)")
	}
	gologger.Info().Msgf("DAST Server API: %s", server.buildURL("/fuzz"))
	gologger.Info().Msgf("DAST Server Stats URL: %s", server.buildURL("/stats"))

	return server, nil
}

func NewStatsServer(fuzzStatsDB *stats.Tracker) (*DASTServer, error) {
	server := &DASTServer{
		nucleiExecutor: &nucleiExecutor{
			executorOpts: protocols.ExecutorOptions{
				FuzzStatsDB: fuzzStatsDB,
			},
		},
	}
	server.setupHandlers(true)
	gologger.Info().Msgf("Stats UI URL: %s", server.buildURL("/stats"))

	return server, nil
}

func (s *DASTServer) Close() {
	s.nucleiExecutor.Close()
	s.echo.Close()
	s.tasksPool.StopAndWaitFor(1 * time.Minute)
}

func (s *DASTServer) buildURL(endpoint string) string {
	values := make(url.Values)
	if s.options.Token != "" {
		values.Set("token", s.options.Token)
	}

	// Use url.URL struct to safely construct the URL
	u := &url.URL{
		Scheme:   "http",
		Host:     s.options.Address,
		Path:     endpoint,
		RawQuery: values.Encode(),
	}
	return u.String()
}

func (s *DASTServer) setupHandlers(onlyStats bool) {
	e := echo.New()
	e.Use(middleware.Recover())
	if s.options.Verbose {
		cfg := middleware.DefaultLoggerConfig
		cfg.Skipper = func(c echo.Context) bool {
			// Skip /stats and /stats.json
			return c.Request().URL.Path == "/stats" || c.Request().URL.Path == "/stats.json"
		}
		e.Use(middleware.LoggerWithConfig(cfg))
	}
	e.Use(middleware.CORS())

	if s.options.Token != "" {
		e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
			KeyLookup: "query:token",
			Validator: func(key string, c echo.Context) (bool, error) {
				return key == s.options.Token, nil
			},
		}))
	}

	e.HideBanner = true
	// POST /fuzz - Queue a request for fuzzing
	if !onlyStats {
		e.POST("/fuzz", s.handleRequest)
	}
	e.GET("/stats", s.handleStats)
	e.GET("/stats.json", s.handleStatsJSON)

	s.echo = e
}

func (s *DASTServer) Start() error {
	if err := s.echo.Start(s.options.Address); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// PostReuestsHandlerRequest is the request body for the /fuzz POST handler.
type PostRequestsHandlerRequest struct {
	RawHTTP string `json:"raw_http"`
	URL     string `json:"url"`
}

func (s *DASTServer) handleRequest(c echo.Context) error {
	var req PostRequestsHandlerRequest
	if err := c.Bind(&req); err != nil {
		fmt.Printf("Error binding request: %s\n", err)
		return err
	}

	// Validate the request
	if req.RawHTTP == "" || req.URL == "" {
		fmt.Printf("Missing required fields\n")
		return c.JSON(400, map[string]string{"error": "missing required fields"})
	}

	s.endpointsInQueue.Add(1)
	s.tasksPool.Submit(func() {
		s.consumeTaskRequest(req)
	})
	return c.NoContent(200)
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
}

func (s *DASTServer) getStats() (StatsResponse, error) {
	cfg := config.DefaultConfig

	resp := StatsResponse{
		DASTServerInfo: DASTServerInfo{
			NucleiVersion:         config.Version,
			NucleiTemplateVersion: cfg.TemplateVersion,
			NucleiDastServerAPI:   s.buildURL("/fuzz"),
			ServerAuthEnabled:     s.options.Token != "",
		},
		DASTScanStartTime: s.startTime,
		DASTScanStatistics: DASTScanStatistics{
			EndpointsInQueue:     s.endpointsInQueue.Load(),
			EndpointsBeingTested: s.endpointsBeingTested.Load(),
			TotalTemplatesLoaded: int64(len(s.nucleiExecutor.store.Templates())),
		},
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

func (s *DASTServer) handleStats(c echo.Context) error {
	stats, err := s.getStats()
	if err != nil {
		return c.JSON(500, map[string]string{"error": err.Error()})
	}

	tmpl, err := template.New("index").Parse(indexTemplate)
	if err != nil {
		return c.JSON(500, map[string]string{"error": err.Error()})
	}
	return tmpl.Execute(c.Response().Writer, stats)
}

func (s *DASTServer) handleStatsJSON(c echo.Context) error {
	resp, err := s.getStats()
	if err != nil {
		return c.JSON(500, map[string]string{"error": err.Error()})
	}
	return c.JSONPretty(200, resp, "  ")
}
