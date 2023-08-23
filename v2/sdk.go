package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
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
	errorutil "github.com/projectdiscovery/utils/errors"
)

// NucleiSDKOptions contains options for nuclei SDK
type NucleiSDKOptions func(e *NucleiEngine) error

// NucleiEngine is the Engine/Client for nuclei which
// runs scans using templates and returns results
type NucleiEngine struct {
	// user options
	resultCallback func(event *output.ResultEvent)

	// unexported core fields
	interactshClient *interactsh.Client
	catalog          *disk.DiskCatalog
	rateLimiter      *ratelimit.Limiter
	store            *loader.Store
	httpxClient      *httpx.HTTPX
	inputProvider    *inputs.SimpleInputProvider
	engine           *core.Engine

	// unexported meta options
	opts           *types.Options
	interactshOpts *interactsh.Options
	hostErrCache   *hosterrorscache.Cache
	customWriter   output.Writer
	customProgress progress.Progress
	rc             reporting.Client
	executerOpts   protocols.ExecutorOptions
}

// LoadAllTemplates loads all nuclei template based on given options
func (e *NucleiEngine) LoadAllTemplates() error {
	workflowLoader, err := parsers.NewLoader(&e.executerOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	e.executerOpts.WorkflowLoader = workflowLoader

	e.store, err = loader.New(loader.NewConfig(e.opts, e.catalog, e.executerOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	e.store.Load()
	return nil
}

// LoadTargets(urls/domains/ips only) adds targets to the nuclei engine
func (e *NucleiEngine) LoadTargets(targets []string, probeNonHttp bool) {
	for _, target := range targets {
		if probeNonHttp {
			e.inputProvider.SetWithProbe(target, e.httpxClient)
		} else {
			e.inputProvider.Set(target)
		}
	}
}

// LoadTargetsFromReader adds targets(urls/domains/ips only) from reader to the nuclei engine
func (e *NucleiEngine) LoadTargetsFromReader(reader io.Reader) {
	buff := bufio.NewScanner(reader)
	for buff.Scan() {
		e.inputProvider.Set(buff.Text())
	}
}

// applyRequiredDefaults to options
func (e *NucleiEngine) applyRequiredDefaults() {
	if e.customWriter == nil {
		e.customWriter = testutils.NewMockOutputWriter()
	}
	if e.customProgress == nil {
		e.customProgress = &testutils.MockProgressClient{}
	}
	if e.hostErrCache == nil {
		e.hostErrCache = hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	}
	// setup interactsh
	if e.interactshOpts != nil {
		e.interactshOpts.Output = e.customWriter
		e.interactshOpts.Progress = e.customProgress
	} else {
		e.interactshOpts = interactsh.DefaultOptions(e.customWriter, e.rc, e.customProgress)
	}
	if e.resultCallback == nil {
		e.resultCallback = func(event *output.ResultEvent) {
			bin, _ := json.Marshal(event)
			fmt.Printf("%v\n", string(bin))
		}
	}
	if e.rateLimiter == nil {
		e.rateLimiter = ratelimit.New(context.Background(), 150, time.Second)
	}
	// these templates are known to have weak matchers
	// and idea is to disable them to avoid false positives
	e.opts.ExcludeTags = config.ReadIgnoreFile().Tags

	e.inputProvider = &inputs.SimpleInputProvider{
		Inputs: []*contextargs.MetaInput{},
	}
}

// init
func (e *NucleiEngine) init() error {
	protocolstate.Init(e.opts)
	protocolinit.Init(e.opts)
	e.applyRequiredDefaults()
	var err error

	if e.rc, err = reporting.New(&reporting.Options{}, ""); err != nil {
		return err
	}
	e.interactshOpts.IssuesClient = e.rc
	if e.interactshClient, err = interactsh.New(e.interactshOpts); err != nil {
		return err
	}

	e.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)

	e.executerOpts = protocols.ExecutorOptions{
		Output:          e.customWriter,
		Options:         e.opts,
		Progress:        e.customProgress,
		Catalog:         e.catalog,
		IssuesClient:    e.rc,
		RateLimiter:     e.rateLimiter,
		Interactsh:      e.interactshClient,
		HostErrorsCache: e.hostErrCache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}

	e.engine = core.New(e.opts)
	e.engine.SetExecuterOptions(e.executerOpts)

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = 5 * time.Second
	if e.httpxClient, err = httpx.New(&httpxOptions); err != nil {
		return err
	}

	return nil
}

// NewNucleiEngine creates a new nuclei engine instance
func NewNucleiEngine(options ...NucleiSDKOptions) (*NucleiEngine, error) {
	// default options
	e := &NucleiEngine{
		opts: types.DefaultOptions(),
	}
	for _, option := range options {
		if err := option(e); err != nil {
			return nil, err
		}
	}
	if err := e.init(); err != nil {
		return nil, err
	}
	return e, nil
}
