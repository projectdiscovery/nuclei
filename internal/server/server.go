package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/alitto/pond"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/server/scope"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
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
	}
	server.setupHandlers()

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
	builder.WriteString(fmt.Sprintf("Using %d parallel tasks with %d buffer", maxWorkers, bufferSize))
	if options.Token != "" {
		builder.WriteString(" (with token)")
	}
	gologger.Info().Msgf("%s", builder.String())
	gologger.Info().Msgf("Connection URL: %s", server.buildConnectionURL())

	return server, nil
}

func (s *DASTServer) Close() {
	s.nucleiExecutor.Close()
	s.echo.Close()
	s.tasksPool.StopAndWaitFor(1 * time.Minute)
}

func (s *DASTServer) buildConnectionURL() string {
	url := fmt.Sprintf("http://%s/requests", s.options.Address)
	if s.options.Token != "" {
		url += "?token=" + s.options.Token
	}
	return url
}

func (s *DASTServer) setupHandlers() {
	e := echo.New()
	e.Use(middleware.Recover())
	if s.options.Verbose {
		e.Use(middleware.Logger())
	}
	e.Use(middleware.CORS())

	if s.options.Token != "" {
		e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
			KeyLookup: "query:token",
			Validator: func(key string, c echo.Context) (bool, error) {
				return key == s.options.Token, nil
			},
			Skipper: func(c echo.Context) bool {
				return c.Path() == "/stats"
			},
		}))
	}

	e.HideBanner = true
	// POST /requests - Queue a request for fuzzing
	e.POST("/requests", s.handleRequest)
	e.GET("/stats", s.handleStats)

	// Serve a Web Server to visualize the stats in a live HTML report
	e.GET("/ui", func(c echo.Context) error {
		return c.File("internal/server/ui/index.html")
	})
	s.echo = e
}

func (s *DASTServer) handleStats(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{})
}

func (s *DASTServer) Start() error {
	return s.echo.Start(s.options.Address)
}

// PostReuestsHandlerRequest is the request body for the /requests POST handler.
type PostReuestsHandlerRequest struct {
	RawHTTP string `json:"raw_http"`
	URL     string `json:"url"`
}

func (s *DASTServer) handleRequest(c echo.Context) error {
	var req PostReuestsHandlerRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	// Validate the request
	if req.RawHTTP == "" || req.URL == "" {
		return c.JSON(400, map[string]string{"error": "missing required fields"})
	}

	s.tasksPool.Submit(func() {
		s.consumeTaskRequest(req)
	})
	return c.NoContent(200)
}
