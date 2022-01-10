package scans

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/updater"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"go.uber.org/ratelimit"
	"gopkg.in/yaml.v3"
)

type PercentReturnFunc func() float64

func makePercentReturnFunc(stats progress.Progress) PercentReturnFunc {
	return PercentReturnFunc(func() float64 {
		return stats.Percent()
	})
}

const defaultMaxHostErrors = 30

// getSettingsForName gets settings for name and returns a types.Options structure
func (s *ScanService) getSettingsForName(name string) (*types.Options, error) {
	setting, err := s.db.GetSettingByName(context.Background(), name)
	if err != nil {
		return nil, err
	}
	settings := &settings.Settings{}
	if yamlErr := yaml.NewDecoder(strings.NewReader(setting.Settingdata)).Decode(settings); yamlErr != nil {
		return nil, yamlErr
	}
	typesOptions := settings.ToTypesOptions()

	// Merge the default ignore config with types.Options
	ignoreFile := &config.IgnoreFile{}

	ignoreFileData := updater.GetIgnoreFile()
	if yamlErr := yaml.NewDecoder(bytes.NewReader(ignoreFileData)).Decode(ignoreFile); yamlErr != nil {
		return nil, yamlErr
	}
	typesOptions.ExcludeTags = append(typesOptions.ExcludeTags, ignoreFile.Tags...)
	typesOptions.ExcludedTemplates = append(typesOptions.ExcludedTemplates, ignoreFile.Files...)
	return typesOptions, nil
}

// createExecuterOpts creates executer options for the scan
func (s *ScanService) createExecuterOpts(ctx context.Context, cancel context.CancelFunc, scanID int64, reportingConfig, scanSource, templatesDirectory string, typesOptions *types.Options) (*scanContext, error) {
	// Use a no ticking progress service to track scan statistics
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	s.Running.Store(scanID, &RunningScan{
		ctx:          ctx,
		cancel:       cancel,
		ProgressFunc: makePercentReturnFunc(progressImpl),
	})

	logWriter, err := s.Logs.Write(scanID)
	if err != nil {
		return nil, err
	}
	buflogWriter := bufio.NewWriter(logWriter)

	outputWriter := newWrappedOutputWriter(s.db, buflogWriter, scanID, scanSource)

	var reportingClient *reporting.Client
	if reportingConfig != "" {
		settings, err := s.db.GetSettingByName(context.Background(), reportingConfig)
		if err != nil {
			return nil, errors.Wrap(err, "could not load reporting config")
		}
		var reportingOptions reporting.Options
		if err := yaml.NewDecoder(strings.NewReader(settings.Settingdata)).Decode(&reportingOptions); err != nil {
			return nil, errors.Wrap(err, "could not decode reporting config")
		}
		reportingClient, err = reporting.New(&reportingOptions, "")
		if err != nil {
			return nil, errors.Wrap(err, "could not create reporting client")
		}
	}

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, progressImpl)
	if typesOptions.InteractshURL != "" {
		interactOpts.ServerURL = typesOptions.InteractshURL
		interactOpts.ServerURL = typesOptions.InteractshURL
		interactOpts.Authorization = typesOptions.InteractshToken
		interactOpts.CacheSize = int64(typesOptions.InteractionsCacheSize)
		interactOpts.Eviction = time.Duration(typesOptions.InteractionsEviction) * time.Second
		interactOpts.CooldownPeriod = time.Duration(typesOptions.InteractionsCoolDownPeriod) * time.Second
		interactOpts.PollDuration = time.Duration(typesOptions.InteractionsPollDuration) * time.Second
	}
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		return nil, errors.Wrap(err, "could not create interactsh client")
	}
	var headlessEngine *engine.Browser
	if typesOptions.Headless {
		headlessEngine, err = engine.New(typesOptions)
		if err != nil {
			return nil, errors.Wrap(err, "could not create headless engine")
		}
	}
	executerOpts := protocols.ExecuterOptions{
		Output:          outputWriter,
		IssuesClient:    reportingClient,
		Options:         typesOptions,
		Progress:        progressImpl,
		Catalog:         catalog.New(templatesDirectory),
		Browser:         headlessEngine,
		Interactsh:      interactClient,
		HostErrorsCache: hosterrorscache.New(defaultMaxHostErrors, hosterrorscache.DefaultMaxHostsCount),
		Colorizer:       aurora.NewAurora(false),
	}
	executerOpts.Catalog.RestrictScope = true // restrict templates directory scope
	if typesOptions.RateLimitMinute > 0 {
		executerOpts.RateLimiter = ratelimit.New(typesOptions.RateLimitMinute, ratelimit.Per(60*time.Second))
	} else {
		executerOpts.RateLimiter = ratelimit.New(typesOptions.RateLimit)
	}
	scanContext := &scanContext{
		logs:         buflogWriter,
		logsFile:     logWriter,
		scanID:       scanID,
		scanService:  s,
		typesOptions: typesOptions,
		executerOpts: executerOpts,
	}
	return scanContext, nil
}

// scanContext contains context information for a scan
type scanContext struct {
	scanID       int64
	executer     *core.Engine
	store        *loader.Store
	logs         *bufio.Writer
	logsFile     io.WriteCloser
	typesOptions *types.Options
	scanService  *ScanService
	executerOpts protocols.ExecuterOptions
}

// Close closes the scan context performing cleanup operations
func (s *scanContext) Close() {
	s.logs.Flush()
	s.logsFile.Close()
	if s.executerOpts.Interactsh != nil {
		s.executerOpts.Interactsh.Close()
	}
	if s.executerOpts.Browser != nil {
		s.executerOpts.Browser.Close()
	}
	if s.executerOpts.IssuesClient != nil {
		s.executerOpts.IssuesClient.Close()
	}
	if s.executerOpts.HostErrorsCache != nil {
		s.executerOpts.HostErrorsCache.Close()
	}

	s.scanService.Running.Delete(s.scanID)

	gologger.Info().Msgf("[scans] [worker] [%d] Closed scan resources", s.scanID)
}

// createExecuterFromOpts creates executer from scanContext
func (s *ScanService) createExecuterFromOpts(scanCtx *scanContext) error {
	workflowLoader, err := parsers.NewLoader(&scanCtx.executerOpts)
	if err != nil {
		return err
	}
	scanCtx.executerOpts.WorkflowLoader = workflowLoader

	loaderConfig := loader.NewConfig(scanCtx.typesOptions, scanCtx.executerOpts.Catalog, scanCtx.executerOpts)
	store, err := loader.New(loaderConfig)
	if err != nil {
		return err
	}
	store.Load()
	scanCtx.store = store

	executer := core.New(scanCtx.typesOptions)
	executer.SetExecuterOptions(scanCtx.executerOpts)
	scanCtx.executer = executer
	return nil
}

// worker is a worker for executing a scan request
func (s *ScanService) worker(req ScanRequest) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mark the scan state as finished in db.
	upateErr := s.db.UpdateScanState(context.Background(), dbsql.UpdateScanStateParams{
		ID:     req.ScanID,
		Status: "started",
	})
	if upateErr != nil {
		return errors.Wrap(upateErr, "could not update started scan state")
	}

	gologger.Info().Msgf("[scans] [worker] [%d] got new scan request", req.ScanID)

	typesOptions, err := s.getSettingsForName(req.Config)
	if err != nil {
		return err
	}
	gologger.Info().Msgf("[scans] [worker] [%d] loaded settings for config %s", req.ScanID, req.Config)

	templatesDirectory, templatesList, workflowsList, err := s.storeTemplatesFromRequest(req.Templates)
	if err != nil {
		return err
	}
	defer os.RemoveAll(templatesDirectory)

	gologger.Info().Msgf("[scans] [worker] [%d] loaded templates and workflows from req %v", req.ScanID, req.Templates)

	typesOptions.TemplatesDirectory = templatesDirectory
	typesOptions.Templates = templatesList
	typesOptions.Workflows = workflowsList

	scanCtx, err := s.createExecuterOpts(ctx, cancel, req.ScanID, req.Reporting, req.ScanSource, templatesDirectory, typesOptions)
	if err != nil {
		return err
	}
	defer scanCtx.Close()

	err = s.createExecuterFromOpts(scanCtx)
	if err != nil {
		return err
	}

	var finalTemplates []*templates.Template
	finalTemplates = append(finalTemplates, scanCtx.store.Templates()...)
	finalTemplates = append(finalTemplates, scanCtx.store.Workflows()...)

	gologger.Info().Msgf("[scans] [worker] [%d] total loaded templates count: %d", req.ScanID, len(finalTemplates))

	inputProvider, err := s.inputProviderFromRequest(req.Targets)
	if err != nil {
		return err
	}
	gologger.Info().Msgf("[scans] [worker] [%d] total loaded input count: %d", req.ScanID, inputProvider.Count())

	scanCtx.executerOpts.Progress.Init(inputProvider.Count(), len(finalTemplates), int64(len(finalTemplates)*int(inputProvider.Count())))
	_ = scanCtx.executer.Execute(ctx, finalTemplates, inputProvider)

	gologger.Info().Msgf("[scans] [worker] [%d] finished scan for ID", req.ScanID)

	for k, v := range scanCtx.executerOpts.Progress.GetMetrics() {
		gologger.Info().Msgf("[scans] [worker] [%d] \tmetric '%s': %v", req.ScanID, k, v)
	}

	// Mark the scan state as finished in db.
	upateErr = s.db.UpdateScanState(context.Background(), dbsql.UpdateScanStateParams{
		ID:     scanCtx.scanID,
		Status: "done",
	})
	if upateErr != nil {
		return errors.Wrap(upateErr, "could not update finished scan state")
	}
	return nil
}
