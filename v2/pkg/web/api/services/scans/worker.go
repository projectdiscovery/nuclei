package scans

import (
	"bufio"
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/settings"
	"go.uber.org/ratelimit"
	"gopkg.in/yaml.v3"
)

type percentReturnFunc func() float64

func makePercentReturnFunc(stats progress.Progress) percentReturnFunc {
	return percentReturnFunc(func() float64 {
		return stats.Percent()
	})
}

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
	return typesOptions, nil
}

// worker is a worker for executing a scan request
func (s *ScanService) worker(req ScanRequest) error {
	typesOptions, err := s.getSettingsForName(req.Config)
	if err != nil {
		return err
	}

	templatesDirectory, templatesList, workflowsList, err := s.storeTemplatesFromRequest(req.Templates)
	if err != nil {
		return err
	}
	defer os.RemoveAll(templatesDirectory)

	typesOptions.TemplatesDirectory = templatesDirectory
	typesOptions.Templates = templatesList
	typesOptions.Workflows = workflowsList

	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	s.running.Store(req.ScanID, makePercentReturnFunc(progressImpl))
	defer func() {
		s.running.Delete(req.ScanID)
	}()

	logWriter, err := s.Logs.Write(req.ScanID)
	if err != nil {
		return err
	}
	defer logWriter.Close()

	buflogWriter := bufio.NewWriter(logWriter)
	defer buflogWriter.Flush()

	outputWriter := newWrappedOutputWriter(s.db, buflogWriter, req.ScanID)

	executerOpts := protocols.ExecuterOptions{
		Output:       outputWriter,
		IssuesClient: nil, //todo: load from config value
		Options:      typesOptions,
		Progress:     progressImpl,
		Catalog:      catalog.New(templatesDirectory),
		RateLimiter:  ratelimit.New(typesOptions.RateLimit),
	}
	if typesOptions.RateLimitMinute > 0 {
		executerOpts.RateLimiter = ratelimit.New(typesOptions.RateLimitMinute, ratelimit.Per(60*time.Second))
	} else {
		executerOpts.RateLimiter = ratelimit.New(typesOptions.RateLimit)
	}

	store, err := loader.New(loader.NewConfig(typesOptions, catalog.New(templatesDirectory), executerOpts))
	if err != nil {
		return err
	}
	store.Load()

	executer := core.New(typesOptions)
	executer.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		return err
	}
	executerOpts.WorkflowLoader = workflowLoader

	var finalTemplates []*templates.Template
	finalTemplates = append(finalTemplates, store.Templates()...)
	finalTemplates = append(finalTemplates, store.Workflows()...)

	inputProvider, err := s.inputProviderFromRequest(req.Targets)
	if err != nil {
		return err
	}
	progressImpl.Init(inputProvider.Count(), len(finalTemplates), int64(len(finalTemplates)*int(inputProvider.Count())))

	_ = executer.Execute(finalTemplates, inputProvider)
	log.Printf("Finish scan for ID: %d\n", req.ScanID)
	return nil
}
