package smartworkflow

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/retryablehttp-go"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Service is a service for automatic smart workflow execution
type Service struct {
	opts       protocols.ExecuterOptions
	store      *loader.Store
	engine     *core.Engine
	target     core.InputProvider
	wappalyzer *wappalyzer.Wappalyze

	results bool
}

// Options contains configuration options for smart workflow service
type Options struct {
	ExecuterOpts protocols.ExecuterOptions
	Store        *loader.Store
	Engine       *core.Engine
	Target       core.InputProvider
}

// Mode options for the smart workflow system
const (
	ModeWorkflow   = "workflow"
	ModeWappalyzer = "wappalyzer"
	ModeAll        = "all"
)

func Modes() string {
	builder := &strings.Builder{}
	builder.WriteString(ModeWorkflow)
	builder.WriteString(",")
	builder.WriteString(ModeWappalyzer)
	builder.WriteString(",")
	builder.WriteString(ModeAll)
	return builder.String()
}

// New takes options and returns a new smart workflow service
func New(opts Options) (*Service, error) {
	wappalyzer, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	return &Service{
		opts:       opts.ExecuterOpts,
		store:      opts.Store,
		engine:     opts.Engine,
		target:     opts.Target,
		wappalyzer: wappalyzer,
	}, nil
}

// Close closes the service
func (s *Service) Close() bool {
	return s.results
}

// Execute performs the execution of smart workflows on provided input
func (s *Service) Execute(mode string) {
	workflowFunc := func() {
		if err := s.executeWorkflowBasedTemplates(); err != nil {
			gologger.Error().Msgf("Could not execute workflow based templates: %s", err)
		}
	}
	wappalyzerFunc := func() map[string][]string {
		mapping, err := s.executeWappalyzerTechDetection()
		if err != nil {
			gologger.Error().Msgf("Could not execute wappalyzer based detection: %s", err)
		}
		return mapping
	}
	modeParts := strings.Split(mode, ",")
	for _, value := range modeParts {
		switch value {
		case ModeWorkflow:
			workflowFunc()
		case ModeWappalyzer:
			mapping := wappalyzerFunc()
			if err := s.executeDiscoveredHostTags(mapping); err != nil {
				gologger.Error().Msgf("Could not execute discovered tags from wappalyzer: %s", err)
			}
		case ModeAll:
			workflowFunc()
			wappalyzerMapping := wappalyzerFunc()

			if err := s.executeDiscoveredHostTags(wappalyzerMapping); err != nil {
				gologger.Error().Msgf("Could not execute discovered tags from technologies: %s", err)
			}
		default:
			gologger.Error().Msgf("Invalid mode value provided to smartworkflows: %s", value)
		}
	}
}

var (
	workflowsTemplateDirectory  = "workflows/"
	defaultTemplatesDirectories = []string{"cves/", "default-logins/", "dns/", "exposures/", "miscellaneous/", "misconfiguration/", "network/", "takeovers/", "vulnerabilities/"}
)

// executeWorkflowBasedTemplates implements the logic to run the default
// workflow templates on the provided input.
func (s *Service) executeWorkflowBasedTemplates() error {
	workflows, err := s.opts.Catalog.GetTemplatePath(workflowsTemplateDirectory)
	if err != nil {
		return errors.Wrap(err, "could not get workflows from directory")
	}
	templates := s.store.LoadWorkflows(workflows)

	gologger.Info().Msgf("[workflow] Executing %d workflows from templates directory on targets", len(templates))
	// s.opts.Progress.AddToTotal() todo: handle stats calculation

	if result := s.engine.Execute(templates, s.target); result.Load() {
		s.results = true
	}
	return nil
}

const maxDefaultBody = 2 * 1024 * 1024

// executeWappalyzerTechDetection implements the logic to run the wappalyzer
// technologies detection on inputs which returns tech.
//
// The returned tags are then used for further execution.
func (s *Service) executeWappalyzerTechDetection() (map[string][]string, error) {
	httpclient, err := httpclientpool.Get(s.opts.Options, &httpclientpool.Configuration{
		Connection: &httpclientpool.ConnectionConfiguration{DisableKeepAlive: true},
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not get http client")
	}

	gologger.Info().Msgf("[workflow] Executing wappalyzer based tech detection on inputs")

	hostTagsMappings := make(map[string][]string)
	// Iterate through each target making http request and identifying fingerprints
	s.target.Scan(func(value string) {
		req, err := retryablehttp.NewRequest(http.MethodGet, value, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", uarand.GetRandom())

		resp, err := httpclient.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return
		}
		reader := io.LimitReader(resp.Body, maxDefaultBody)
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		fingerprints := s.wappalyzer.Fingerprint(resp.Header, data)
		items := make([]string, 0, len(fingerprints))
		for k := range fingerprints {
			items = append(items, strings.ToLower(k))
		}
		hostTagsMappings[value] = items
	})
	return hostTagsMappings, nil
}

// executeDiscoveredTagsOnTemplates takes a list of hosts and tags and runs templates
// that match these unique tags in directories other than technologies/panels/workflows.
func (s *Service) executeDiscoveredHostTags(data map[string][]string) error {
	gologger.Info().Msgf("Executing %d discovered host->tech mappings", len(data))

	var allTemplates []string
	// Collect path for default directories we want to look for templates in
	for _, directory := range defaultTemplatesDirectories {
		templates, err := s.opts.Catalog.GetTemplatePath(directory)
		if err != nil {
			return errors.Wrap(err, "could not get templates in directory")
		}
		allTemplates = append(allTemplates, templates...)
	}

	childExecuter := s.engine.ChildExecuter()

	for k, v := range data {
		templates := s.store.LoadTemplatesWithTags(allTemplates, v)

		gologger.Info().Msgf("Executing tags %v for host %s (%d templates)", v, k, len(templates))
		for _, template := range templates {
			childExecuter.Execute(template, k)
		}
	}
	results := childExecuter.Close()
	if results.Load() {
		s.results = true
	}
	return nil
}
