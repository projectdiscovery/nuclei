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
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
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
	ModeWorkflow     = "workflow"
	ModeTechnologies = "technologies"
	ModeWappalyzer   = "wappalyzer"
	ModeAll          = "all"
)

func Modes() string {
	builder := &strings.Builder{}
	builder.WriteString(ModeWorkflow)
	builder.WriteString(",")
	builder.WriteString(ModeTechnologies)
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
	technologiesFunc := func() map[string][]string {
		mapping, err := s.executeTechnologiesPanelsBasedTemplates()
		if err != nil {
			gologger.Error().Msgf("Could not execute technologies based templates: %s", err)
		}
		return mapping
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
		case ModeTechnologies:
			mapping := technologiesFunc()
			if err := s.executeDiscoveredHostTags(mapping); err != nil {
				gologger.Error().Msgf("Could not execute discovered tags from technologies: %s", err)
			}
		case ModeWappalyzer:
			mapping := wappalyzerFunc()
			if err := s.executeDiscoveredHostTags(mapping); err != nil {
				gologger.Error().Msgf("Could not execute discovered tags from wappalyzer: %s", err)
			}
		case ModeAll:
			workflowFunc()
			technologiesMapping := technologiesFunc()
			wappalyzerMapping := wappalyzerFunc()
			mapping := deduplicateHostMappings(technologiesMapping, wappalyzerMapping)

			if err := s.executeDiscoveredHostTags(mapping); err != nil {
				gologger.Error().Msgf("Could not execute discovered tags from technologies: %s", err)
			}
		default:
			gologger.Error().Msgf("Invalid mode value provided to smartworkflows: %s", value)
		}
	}
}

var (
	workflowsTemplateDirectory     = "workflows/"
	exposedPanelsTemplateDirectory = "exposed-panels/"
	technologiesTemplateDirectory  = "technologies/"

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

// executeTechnologiesPanelsBasedTemplates implements the logic to run the default
// technologies and panels templates on the provided input.
//
// The returned tags are then used for further execution.
func (s *Service) executeTechnologiesPanelsBasedTemplates() (map[string][]string, error) {
	panels, err := s.opts.Catalog.GetTemplatePath(exposedPanelsTemplateDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "could not get exposed-panels from directory")
	}
	technologies, err := s.opts.Catalog.GetTemplatePath(technologiesTemplateDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "could not get technologies from directory")
	}
	templateList := append(panels, technologies...)
	templatesSlice := s.store.LoadTemplates(templateList)
	finalTemplates, _ := templates.ClusterTemplates(templatesSlice, s.opts)

	gologger.Info().Msgf("[workflow] Executing %d techs and panels from templates directory on targets", len(finalTemplates))

	hostTagsMappings := make(map[string][]string)
	s.engine.ExecuteWithResults(finalTemplates, s.target, func(event *output.ResultEvent) {
		if values, ok := hostTagsMappings[event.Host]; ok {
			hostTagsMappings[event.Host] = append(values, collectNamesFromResultEvent(event)...)
		} else {
			hostTagsMappings[event.Host] = collectNamesFromResultEvent(event)
		}
	})
	finalMapping := cleanupHostTagsMappings(hostTagsMappings)
	return finalMapping, nil
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

// cleanupHostTagsMappings cleans up host->tags mapping by doing deduplication
// over the entire data structure and recommending best tech mapping per host.
//
// It is used during technologies and exposed-panels execution
func cleanupHostTagsMappings(data map[string][]string) map[string][]string {
	// first pass to identify tag frequency
	techReferenceCount := make(map[string]int)
	for _, v := range data {
		for _, item := range v {
			if count, ok := techReferenceCount[item]; !ok {
				techReferenceCount[item] = 1
			} else {
				techReferenceCount[item] = count + 1
			}
		}
	}

	highest, lowest, avg := 0, 0, 0
	for _, v := range techReferenceCount {
		if highest == 0 {
			highest = v
		}
		if lowest == 0 {
			lowest = v
		}
		if v > highest {
			highest = v
		}
		if v < lowest {
			lowest = v
		}
	}
	avg = (highest + lowest) / 2

	results := make(map[string][]string)
	// Second pass to eliminate duplicate matches
	for k, v := range data {
		var unique []string

		for _, item := range v {
			if count, ok := techReferenceCount[item]; ok && count > avg {
				continue
			} else {
				unique = append(unique, item)
			}
		}
		results[k] = unique
	}
	return results
}

// deduplicateHostMappings performs deduplication of two host mappings
func deduplicateHostMappings(first, second map[string][]string) map[string][]string {
	final := make(map[string][]string, len(first))
	for k, v := range first {
		if previous, ok := final[k]; !ok {
			final[k] = v
		} else {
			final[k] = appendSliceUnique(previous, v)
		}
	}
	return final
}

func appendSliceUnique(slice, second []string) []string {
	unique := make(map[string]struct{})
	for _, v := range slice {
		unique[v] = struct{}{}
	}
	for _, v := range second {
		unique[v] = struct{}{}
	}
	final := make([]string, 0, len(unique))
	for k := range unique {
		final = append(final, k)
	}
	return final
}

func collectNamesFromResultEvent(event *output.ResultEvent) []string {
	tags := event.Info.Tags.ToSlice()
	values := make([]string, 0, 2+len(tags))

	if event.MatcherName != "" {
		values = append(values, event.MatcherName)
	}
	if event.ExtractorName != "" {
		values = append(values, event.ExtractorName)
	}
	if len(tags) > 0 {
		values = append(values, tags...)
	}
	return values
}
