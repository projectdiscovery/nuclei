package server

import (
	"context"
	"fmt"
	_ "net/http/pprof"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/projectfile"
	"gopkg.in/yaml.v3"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/parser"
	parsers "github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/excludematchers"
	browserEngine "github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type nucleiExecutor struct {
	engine       *core.Engine
	store        *loader.Store
	options      *NucleiExecutorOptions
	executorOpts protocols.ExecutorOptions
}

type NucleiExecutorOptions struct {
	Options            *types.Options
	Output             output.Writer
	Progress           progress.Progress
	Catalog            catalog.Catalog
	IssuesClient       reporting.Client
	RateLimiter        *ratelimit.Limiter
	Interactsh         *interactsh.Client
	ProjectFile        *projectfile.ProjectFile
	Browser            *browserEngine.Browser
	FuzzStatsDB        *stats.Tracker
	Colorizer          aurora.Aurora
	Parser             parser.Parser
	TemporaryDirectory string
}

func newNucleiExecutor(opts *NucleiExecutorOptions) (*nucleiExecutor, error) {
	fuzzFreqCache := frequency.New(frequency.DefaultMaxTrackCount, opts.Options.FuzzParamFrequency)
	resumeCfg := types.NewResumeCfg()

	// Create the executor options which will be used throughout the execution
	// stage by the nuclei engine modules.
	executorOpts := protocols.ExecutorOptions{
		Output:              opts.Output,
		Options:             opts.Options,
		Progress:            opts.Progress,
		Catalog:             opts.Catalog,
		IssuesClient:        opts.IssuesClient,
		RateLimiter:         opts.RateLimiter,
		Interactsh:          opts.Interactsh,
		ProjectFile:         opts.ProjectFile,
		Browser:             opts.Browser,
		Colorizer:           opts.Colorizer,
		ResumeCfg:           resumeCfg,
		ExcludeMatchers:     excludematchers.New(opts.Options.ExcludeMatchers),
		InputHelper:         input.NewHelper(),
		TemporaryDirectory:  opts.TemporaryDirectory,
		Parser:              opts.Parser,
		FuzzParamsFrequency: fuzzFreqCache,
		GlobalMatchers:      globalmatchers.New(),
		FuzzStatsDB:         opts.FuzzStatsDB,
	}

	if opts.Options.ShouldUseHostError() {
		maxHostError := opts.Options.MaxHostError
		if maxHostError == 30 {
			maxHostError = 100 // auto adjust for fuzzings
		}
		if opts.Options.TemplateThreads > maxHostError {
			gologger.Info().Msgf("Adjusting max-host-error to the concurrency value: %d", opts.Options.TemplateThreads)

			maxHostError = opts.Options.TemplateThreads
		}

		cache := hosterrorscache.New(maxHostError, hosterrorscache.DefaultMaxHostsCount, opts.Options.TrackError)
		cache.SetVerbose(opts.Options.Verbose)

		executorOpts.HostErrorsCache = cache
	}

	executorEngine := core.New(opts.Options)
	executorEngine.SetExecuterOptions(executorOpts)

	workflowLoader, err := parsers.NewLoader(&executorOpts)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create loader options.")
	}
	executorOpts.WorkflowLoader = workflowLoader

	// If using input-file flags, only load http fuzzing based templates.
	loaderConfig := loader.NewConfig(opts.Options, opts.Catalog, executorOpts)
	if !strings.EqualFold(opts.Options.InputFileMode, "list") || opts.Options.DAST || opts.Options.DASTServer {
		// if input type is not list (implicitly enable fuzzing)
		opts.Options.DAST = true
	}
	store, err := loader.New(loaderConfig)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create loader options.")
	}
	store.Load()

	return &nucleiExecutor{
		engine:       executorEngine,
		store:        store,
		options:      opts,
		executorOpts: executorOpts,
	}, nil
}

// proxifyRequest is a request for proxify
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header map[string]string `json:"header"`
		Body   string            `json:"body"`
		Raw    string            `json:"raw"`
	} `json:"request"`
}

func (n *nucleiExecutor) ExecuteScan(target PostRequestsHandlerRequest) error {
	finalTemplates := []*templates.Template{}
	finalTemplates = append(finalTemplates, n.store.Templates()...)
	finalTemplates = append(finalTemplates, n.store.Workflows()...)

	if len(finalTemplates) == 0 {
		return errors.New("no templates provided for scan")
	}

	payload := proxifyRequest{
		URL: target.URL,
		Request: struct {
			Header map[string]string `json:"header"`
			Body   string            `json:"body"`
			Raw    string            `json:"raw"`
		}{
			Raw: target.RawHTTP,
		},
	}

	marshalledYaml, err := yaml.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling yaml: %s", err)
	}

	inputProvider, err := http.NewHttpInputProvider(&http.HttpMultiFormatOptions{
		InputContents: string(marshalledYaml),
		InputMode:     "yaml",
		Options: formats.InputFormatOptions{
			Variables: make(map[string]interface{}),
		},
	})
	if err != nil {
		return errors.Wrap(err, "could not create input provider")
	}

	// We don't care about the result as its a boolean
	// stating whether we got matches or not
	_ = n.engine.ExecuteScanWithOpts(context.Background(), finalTemplates, inputProvider, true)
	return nil
}

func (n *nucleiExecutor) Close() {
	if n.executorOpts.FuzzStatsDB != nil {
		n.executorOpts.FuzzStatsDB.Close()
	}
	if n.options.Interactsh != nil {
		_ = n.options.Interactsh.Close()
	}
	if n.executorOpts.InputHelper != nil {
		_ = n.executorOpts.InputHelper.Close()
	}

}
