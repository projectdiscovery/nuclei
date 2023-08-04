package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

func main() {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		fmt.Printf("Got Result: %v\n", event)
	}

	defaultOpts := types.DefaultOptions()
	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	defaultOpts.IncludeIds = goflags.StringSlice{"cname-service", "tech-detect"}
	defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		log.Fatalf("Could not create interact client: %s\n", err)
	}
	defer interactClient.Close()

	home, _ := os.UserHomeDir()
	catalog := disk.NewCatalog(filepath.Join(home, "nuclei-templates"))
	executerOpts := protocols.ExecutorOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
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
		log.Fatalf("Could not create loader client: %s\n", err)
	}
	store.Load()

	// flat input without probe
	inputArgs := []*contextargs.MetaInput{{Input: "docs.hackerone.com"}}
	input := &inputs.SimpleInputProvider{Inputs: inputArgs}

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = 5 * time.Second
	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		log.Fatal(err)
	}

	// use httpx to probe the URL => https://scanme.sh
	input.SetWithProbe("scanme.sh", httpxClient)

	_ = engine.Execute(store.Templates(), input)
	engine.WorkPool().Wait() // Wait for the scan to finish
}
