package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/server/scope"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/sourcegraph/conc/pool"
)

// DASTServer is a server that performs execution of fuzzing templates
// on user input passed to the API.
type DASTServer struct {
	echo         *echo.Echo
	options      *Options
	tasksPool    *pool.Pool
	deduplicator *requestDeduplicator
	scopeManager *scope.Manager
	fuzzRequests chan PostReuestsHandlerRequest
}

// Options contains the configuration options for the server.
type Options struct {
	// Address is the address to bind the server to
	Address string
	// Token is the token to use for authentication (optional)
	Token string
	// Concurrency is the concurrency level to use for the targets
	Concurrency int
	// Templates is the list of templates to use for fuzzing
	Templates []string
	// Verbose is a flag that controls verbose output
	Verbose bool

	// Scope fields for fuzzer
	InScope  []string
	OutScope []string

	OutputWriter output.Writer
}

// New creates a new instance of the DAST server.
func New(options *Options) (*DASTServer, error) {
	bufferSize := options.Concurrency * 100

	// If the user has specified no templates, use the default ones
	// for DAST only.
	if len(options.Templates) == 0 {
		options.Templates = []string{"dast/"}
	}
	server := &DASTServer{
		options:      options,
		tasksPool:    pool.New().WithMaxGoroutines(options.Concurrency),
		deduplicator: newRequestDeduplicator(),
		fuzzRequests: make(chan PostReuestsHandlerRequest, bufferSize),
	}
	server.setupHandlers()
	server.setupWorkers()

	scopeManager, err := scope.NewManager(
		options.InScope,
		options.OutScope,
	)
	if err != nil {
		return nil, err
	}
	server.scopeManager = scopeManager

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Using %d parallel tasks with %d buffer", options.Concurrency, bufferSize))
	if options.Token != "" {
		builder.WriteString(" (with token)")
	}
	gologger.Info().Msgf(builder.String())
	gologger.Info().Msgf("Connection URL: %s", server.buildConnectionURL())

	return server, nil
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
		}))
	}

	e.HideBanner = true
	// POST /requests - Queue a request for fuzzing
	e.POST("/requests", s.handleRequest)
	s.echo = e
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

	if s.options.Verbose {
		marshalIndented, _ := json.MarshalIndent(req, "", "  ")
		gologger.Verbose().Msgf("Received request: %s", marshalIndented)
	}

	select {
	case s.fuzzRequests <- req:
		return c.NoContent(200)
	case timeout := <-time.After(5 * time.Second):
		return c.JSON(429, map[string]string{"error": fmt.Sprintf("server busy, try again after %v", timeout)})
	}
}
