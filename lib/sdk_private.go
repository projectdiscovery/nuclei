package nuclei

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/input"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	nucleiUtils "github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/ratelimit"
)

var sharedInit *sync.Once

// applyRequiredDefaults to options
func (e *NucleiEngine) applyRequiredDefaults(ctx context.Context) {
	mockoutput := testutils.NewMockOutputWriter(e.opts.OmitTemplate)
	mockoutput.WriteCallback = func(event *output.ResultEvent) {
		if len(e.resultCallbacks) > 0 {
			for _, callback := range e.resultCallbacks {
				if callback != nil {
					callback(event)
				}
			}
			return
		}
		sb := strings.Builder{}
		sb.WriteString(fmt.Sprintf("[%v] ", event.TemplateID))
		if event.Matched != "" {
			sb.WriteString(event.Matched)
		} else {
			sb.WriteString(event.Host)
		}
		fmt.Println(sb.String())
	}
	if e.onFailureCallback != nil {
		mockoutput.FailureCallback = e.onFailureCallback
	}

	if e.customWriter != nil {
		e.customWriter = output.NewMultiWriter(e.customWriter, mockoutput)
	} else {
		e.customWriter = mockoutput
	}

	if e.customProgress == nil {
		e.customProgress = &testutils.MockProgressClient{}
	}
	if e.hostErrCache == nil && e.opts.ShouldUseHostError() {
		e.hostErrCache = hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	}
	// setup interactsh
	if e.interactshOpts != nil {
		e.interactshOpts.Output = e.customWriter
		e.interactshOpts.Progress = e.customProgress
	} else {
		e.interactshOpts = interactsh.DefaultOptions(e.customWriter, e.rc, e.customProgress)
	}
	if e.rateLimiter == nil {
		e.rateLimiter = ratelimit.New(ctx, 150, time.Second)
	}
	if e.opts.ExcludeTags == nil {
		e.opts.ExcludeTags = []string{}
	}
	// these templates are known to have weak matchers
	// and idea is to disable them to avoid false positives
	e.opts.ExcludeTags = append(e.opts.ExcludeTags, config.ReadIgnoreFile().Tags...)

	e.inputProvider = provider.NewSimpleInputProvider()
}

// init
func (e *NucleiEngine) init(ctx context.Context) error {
	if e.opts.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else if e.opts.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else if e.opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if err := runner.ValidateOptions(e.opts); err != nil {
		return err
	}

	e.parser = templates.NewParser()

	if sharedInit == nil || protocolstate.ShouldInit() {
		sharedInit = &sync.Once{}
	}

	sharedInit.Do(func() {
		_ = protocolinit.Init(e.opts)
	})

	if e.opts.ProxyInternal && e.opts.AliveHttpProxy != "" || e.opts.AliveSocksProxy != "" {
		httpclient, err := httpclientpool.Get(e.opts, &httpclientpool.Configuration{})
		if err != nil {
			return err
		}
		e.httpClient = httpclient
	}

	e.applyRequiredDefaults(ctx)
	var err error

	// setup progressbar
	if e.enableStats {
		progressInstance, progressErr := progress.NewStatsTicker(e.opts.StatsInterval, e.enableStats, e.opts.StatsJSON, false, e.opts.MetricsPort)
		if progressErr != nil {
			return err
		}
		e.customProgress = progressInstance
		e.interactshOpts.Progress = progressInstance
	}

	if err := reporting.CreateConfigIfNotExists(); err != nil {
		return err
	}
	// we don't support reporting config in sdk mode
	if e.rc, err = reporting.New(&reporting.Options{}, "", false); err != nil {
		return err
	}
	e.interactshOpts.IssuesClient = e.rc
	if e.httpClient != nil {
		e.interactshOpts.HTTPClient = e.httpClient
	}
	if e.interactshClient, err = interactsh.New(e.interactshOpts); err != nil {
		return err
	}

	if e.catalog == nil {
		e.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	}

	e.executerOpts = protocols.ExecutorOptions{
		Output:       e.customWriter,
		Options:      e.opts,
		Progress:     e.customProgress,
		Catalog:      e.catalog,
		IssuesClient: e.rc,
		RateLimiter:  e.rateLimiter,
		Interactsh:   e.interactshClient,
		Colorizer:    aurora.NewAurora(true),
		ResumeCfg:    types.NewResumeCfg(),
		Browser:      e.browserInstance,
		Parser:       e.parser,
		InputHelper:  input.NewHelper(),
	}
	if e.opts.ShouldUseHostError() && e.hostErrCache != nil {
		e.executerOpts.HostErrorsCache = e.hostErrCache
	}
	if len(e.opts.SecretsFile) > 0 {
		authTmplStore, err := runner.GetAuthTmplStore(*e.opts, e.catalog, e.executerOpts)
		if err != nil {
			return errors.Wrap(err, "failed to load dynamic auth templates")
		}
		authOpts := &authprovider.AuthProviderOptions{SecretsFiles: e.opts.SecretsFile}
		authOpts.LazyFetchSecret = runner.GetLazyAuthFetchCallback(&runner.AuthLazyFetchOptions{
			TemplateStore: authTmplStore,
			ExecOpts:      e.executerOpts,
		})
		// initialize auth provider
		provider, err := authprovider.NewAuthProvider(authOpts)
		if err != nil {
			return errors.Wrap(err, "could not create auth provider")
		}
		e.executerOpts.AuthProvider = provider
	}
	if e.authprovider != nil {
		e.executerOpts.AuthProvider = e.authprovider
	}

	// prefetch secrets
	if e.executerOpts.AuthProvider != nil && e.opts.PreFetchSecrets {
		if err := e.executerOpts.AuthProvider.PreFetchSecrets(); err != nil {
			return errors.Wrap(err, "could not prefetch secrets")
		}
	}

	if e.executerOpts.RateLimiter == nil {
		if e.opts.RateLimitMinute > 0 {
			e.opts.RateLimit = e.opts.RateLimitMinute
			e.opts.RateLimitDuration = time.Minute
		}
		if e.opts.RateLimit > 0 && e.opts.RateLimitDuration == 0 {
			e.opts.RateLimitDuration = time.Second
		}
		if e.opts.RateLimit == 0 && e.opts.RateLimitDuration == 0 {
			e.executerOpts.RateLimiter = ratelimit.NewUnlimited(ctx)
		} else {
			e.executerOpts.RateLimiter = ratelimit.New(ctx, uint(e.opts.RateLimit), e.opts.RateLimitDuration)
		}
	}

	e.engine = core.New(e.opts)
	e.engine.SetExecuterOptions(e.executerOpts)

	httpxOptions := httpx.DefaultOptions
	httpxOptions.Timeout = 5 * time.Second
	if client, err := httpx.New(&httpxOptions); err != nil {
		return err
	} else {
		e.httpxClient = nucleiUtils.GetInputLivenessChecker(client)
	}

	// Only Happens once regardless how many times this function is called
	// This will update ignore file to filter out templates with weak matchers to avoid false positives
	// and also upgrade templates to latest version if available
	installer.NucleiSDKVersionCheck()

	if DefaultConfig.CanCheckForUpdates() {
		return e.processUpdateCheckResults()
	}
	return nil
}

type syncOnce struct {
	sync.Once
}

var updateCheckInstance = &syncOnce{}

// processUpdateCheckResults processes update check results
func (e *NucleiEngine) processUpdateCheckResults() error {
	var err error
	updateCheckInstance.Do(func() {
		if e.onUpdateAvailableCallback != nil {
			e.onUpdateAvailableCallback(config.DefaultConfig.LatestNucleiTemplatesVersion)
		}
		tm := installer.TemplateManager{}
		err = tm.UpdateIfOutdated()
	})
	return err
}
