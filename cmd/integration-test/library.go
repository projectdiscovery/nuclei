package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	parsers "github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

var libraryTestcases = []TestCaseInfo{
	{Path: "library/test.yaml", TestCase: &goIntegrationTest{}},
	{Path: "library/test.json", TestCase: &goIntegrationTest{}},
}

type goIntegrationTest struct{}

// Execute executes a test case and returns an error if occurred
//
// Execute the docs at ../DESIGN.md if the code stops working for integration.
func (h *goIntegrationTest) Execute(templatePath string) error {
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = fmt.Fprintf(w, "This is test matcher text")
		if strings.EqualFold(r.Header.Get("test"), "nuclei") {
			_, _ = fmt.Fprintf(w, "This is test headers matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := executeNucleiAsLibrary(templatePath, ts.URL)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// executeNucleiAsLibrary contains an example
func executeNucleiAsLibrary(templatePath, templateURL string) ([]string, error) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, err := reporting.New(&reporting.Options{}, "", false)
	if err != nil {
		return nil, err
	}
	defer reportingClient.Close()

	defaultOpts := types.DefaultOptions()
	_ = protocolstate.Init(defaultOpts)
	_ = protocolinit.Init(defaultOpts)

	defaultOpts.Templates = goflags.StringSlice{templatePath}
	defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	outputWriter := testutils.NewMockOutputWriter(defaultOpts.OmitTemplate)
	var results []string
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		results = append(results, fmt.Sprintf("%v\n", event))
	}

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		return nil, errors.Wrap(err, "could not create interact client")
	}
	defer interactClient.Close()

	home, _ := os.UserHomeDir()
	catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
	ratelimiter := ratelimit.New(context.Background(), 150, time.Second)
	defer ratelimiter.Stop()

	executerOpts := protocols.ExecutorOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimiter,
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
		Parser:          templates.NewParser(),
	}
	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(defaultOpts, catalog, executerOpts))
	if err != nil {
		return nil, errors.Wrap(err, "could not create loader")
	}
	store.Load()

	_ = engine.Execute(context.Background(), store.Templates(), provider.NewSimpleInputProviderWithUrls(templateURL))
	engine.WorkPool().Wait() // Wait for the scan to finish

	return results, nil
}
