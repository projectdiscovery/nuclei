package automaticscan

import (
	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Service is a service for automatic scan execution
type Service struct {
	opts          protocols.ExecutorOptions
	store         *loader.Store
	engine        *core.Engine
	target        core.InputProvider
	wappalyzer    *wappalyzer.Wappalyze
	childExecuter *core.ChildExecuter
	httpclient    *retryablehttp.Client

	results            bool
	allTemplates       []string
	technologyMappings map[string]string
	techTemplates      []*templates.Template
}

// Options contains configuration options for automatic scan service
type Options struct {
	ExecuterOpts protocols.ExecutorOptions
	Store        *loader.Store
	Engine       *core.Engine
	Target       core.InputProvider
}

const mappingFilename = "wappalyzer-mapping.yml"

// New takes options and returns a new automatic scan service
func New(opts Options) (*Service, error) {
	wappalyzer, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	var mappingData map[string]string
	config := config.DefaultConfig

	mappingFile := filepath.Join(config.TemplatesDirectory, mappingFilename)
	if file, err := os.Open(mappingFile); err == nil {
		_ = yaml.NewDecoder(file).Decode(&mappingData)
		file.Close()
	}

	if opts.ExecuterOpts.Options.Verbose {
		gologger.Verbose().Msgf("Normalized mapping (%d): %v\n", len(mappingData), mappingData)
	}
	defaultTemplatesDirectories := []string{config.TemplatesDirectory}

	// adding custom template path if available
	if len(opts.ExecuterOpts.Options.Templates) > 0 {
		defaultTemplatesDirectories = append(defaultTemplatesDirectories, opts.ExecuterOpts.Options.Templates...)
	}
	// Collect path for default directories we want to look for templates in
	var allTemplates []string
	for _, directory := range defaultTemplatesDirectories {
		templates, err := opts.ExecuterOpts.Catalog.GetTemplatePath(directory)
		if err != nil {
			return nil, errors.Wrap(err, "could not get templates in directory")
		}
		allTemplates = append(allTemplates, templates...)
	}
	tagTemplates := opts.Store.LoadTemplatesWithTags(allTemplates, []string{"tech"})
	if len(tagTemplates) == 0 {
		return nil, errors.New("could not find any templates with tech tag")
	}
	tagTemplates, _ = templates.ClusterTemplates(tagTemplates, opts.ExecuterOpts)
	gologger.Info().Msgf("Loaded %d cluster templates from the tech tag.\n", len(tagTemplates))

	childExecuter := opts.Engine.ChildExecuter()

	httpclient, err := httpclientpool.Get(opts.ExecuterOpts.Options, &httpclientpool.Configuration{
		Connection: &httpclientpool.ConnectionConfiguration{
			DisableKeepAlive: httputil.ShouldDisableKeepAlive(opts.ExecuterOpts.Options),
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not get http client")
	}

	return &Service{
		opts:               opts.ExecuterOpts,
		store:              opts.Store,
		engine:             opts.Engine,
		target:             opts.Target,
		wappalyzer:         wappalyzer,
		allTemplates:       allTemplates,
		childExecuter:      childExecuter,
		httpclient:         httpclient,
		technologyMappings: mappingData,
		techTemplates:      tagTemplates,
	}, nil
}

// Close closes the service
func (s *Service) Close() bool {
	results := s.childExecuter.Close()
	if results.Load() {
		s.results = true
	}
	return s.results
}

// Execute performs the execution of automatic scan on provided input
func (s *Service) Execute() {
	if err := s.executeHybridTechDetection(); err != nil {
		gologger.Error().Msgf("Could not execute wappalyzer based detection: %s", err)
	}
}

const maxDefaultBody = 2 * 1024 * 1024

// executeWappalyzerTechDetection implements the logic to run the wappalyzer
// technologies detection on inputs which returns tech.
//
// The returned tags are then used for further execution.
func (s *Service) executeHybridTechDetection() error {
	gologger.Info().Msgf("Executing wappalyzer based tech detection on input urls")

	// Iterate through each target making http request and identifying fingerprints
	inputPool := s.engine.WorkPool().InputPool(types.HTTPProtocol)

	s.target.Scan(func(value *contextargs.MetaInput) bool {
		inputPool.WaitGroup.Add()

		go func(input *contextargs.MetaInput) {
			defer inputPool.WaitGroup.Done()

			s.processHybridInputPair(input)
		}(value)
		return true
	})
	inputPool.WaitGroup.Wait()
	return nil
}

func (s *Service) getTechUseWappalyzer(input *contextargs.MetaInput) []string {
	req, err := retryablehttp.NewRequest(http.MethodGet, input.Input, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := s.httpclient.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	reader := io.LimitReader(resp.Body, maxDefaultBody)
	data, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return nil
	}
	resp.Body.Close()

	fingerprints := s.wappalyzer.Fingerprint(resp.Header, data)
	normalized := make(map[string]struct{})
	for k := range fingerprints {
		normalized[normalizeAppName(k)] = struct{}{}
	}

	if s.opts.Options.Verbose {
		gologger.Verbose().Msgf("Wappalyzer fingerprints %v for %s\n", normalized, input)
	}

	for k := range normalized {
		// Replace values with mapping data
		if value, ok := s.technologyMappings[k]; ok {
			delete(normalized, k)
			normalized[value] = struct{}{}
		}
	}

	items := make([]string, 0, len(normalized))
	for k := range normalized {
		if strings.Contains(k, " ") {
			parts := strings.Split(strings.ToLower(k), " ")
			items = append(items, parts...)
		} else {
			items = append(items, strings.ToLower(k))
		}
	}
	return sliceutil.Dedupe(items)
}

func (s *Service) getTechUseDetectTemplate(input *contextargs.MetaInput) ([]string, []string) {
	ctxArgs := contextargs.New()
	ctxArgs.MetaInput = input
	inputPool := s.engine.WorkPool().InputPool(types.HTTPProtocol)

	resultsChan := make(chan []*output.ResultEvent)
	resultsSlice := make([][]*output.ResultEvent, 0)

	successTags := make([]string, 0)
	successTemplateName := make([]string, 0)
	var resultsWaitGroup sync.WaitGroup
	resultsWaitGroup.Add(1)
	go func() {
		defer resultsWaitGroup.Done()
		for result := range resultsChan {
			resultsSlice = append(resultsSlice, result)
		}
	}()
	for _, t := range s.techTemplates {
		inputPool.WaitGroup.Add()
		go func(template *templates.Template) {
			defer inputPool.WaitGroup.Done()
			ctx := scan.NewScanContext(ctxArgs)
			ctx.OnResult = func(event *output.InternalWrappedEvent) {
				if event == nil {
					// something went wrong
					return
				}
				// If no results were found, and also interactsh is not being used
				// in that case we can skip it, otherwise we've to show failure in
				// case of matcher-status flag.
				if event.HasOperatorResult() || event.UsesInteractsh {
					writer.WriteResult(event, s.opts.Output, s.opts.Progress, s.opts.IssuesClient)
				}
			}
			results, err := template.Executer.ExecuteWithResults(ctx)
			if err != nil {
				gologger.Error().Msgf("error executing template: %s with error: %s\n", template.Info.Name, err)
				return
			}
			if len(results) > 0 {
				resultsChan <- results
			}
		}(t)
	}
	inputPool.WaitGroup.Wait()
	close(resultsChan)
	resultsWaitGroup.Wait()
	for _, results := range resultsSlice {
		for _, r := range results {
			successTags = append(successTags, r.Info.Tags.ToSlice()...)
			// Collect the technologies specified in the matcher.name.
			if len(r.MatcherName) != 0 {
				successTags = append(successTags, r.MatcherName)
			}
			successTemplateName = append(successTemplateName, r.TemplateID)
		}
	}

	return sliceutil.Dedupe(successTags), successTemplateName
}

func (s *Service) processHybridInputPair(input *contextargs.MetaInput) {
	successTags := make([]string, 0)
	tagsUseWappalyzer := s.getTechUseWappalyzer(input)
	tagsUseDetectTemplate, successTemplateName := s.getTechUseDetectTemplate(input)
	gologger.Info().Msgf("Executing Wappalyzer based tech detection get (%v) for host %s", strings.Join(tagsUseWappalyzer, ", "), input)
	gologger.Info().Msgf("Executing Template based tech detection get (%v) for host %s", strings.Join(tagsUseDetectTemplate, ", "), input)
	successTags = append(successTags, tagsUseWappalyzer...)
	successTags = append(successTags, tagsUseDetectTemplate...)
	successTags = append(successTags, s.opts.Options.Tags...)
	uniqueTags := sliceutil.Dedupe(successTags)

	var tags []string
	// delete tech tag
	for _, tag := range uniqueTags {
		if tag == "tech" || tag == "waf" || tag == "favicon" {
			continue
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		return
	}
	templatesList := s.store.LoadTemplatesWithTags(s.allTemplates, tags)
	finallyTemplates := make([]*templates.Template, 0)
	// delete templates which are already executed
	for _, t := range templatesList {
		if sliceutil.Contains(successTemplateName, t.ID) {
			continue
		}
		finallyTemplates = append(finallyTemplates, t)
	}
	gologger.Info().Msgf("Executing tags (%v) for host %s (%d templates)", strings.Join(tags, ", "), input, len(templatesList))
	finallyTemplates, _ = templates.ClusterTemplates(finallyTemplates, s.opts)
	for _, t := range finallyTemplates {
		s.opts.Progress.AddToTotal(int64(t.Executer.Requests()))

		if s.opts.Options.VerboseVerbose {
			gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(t.ID,
				t.Info.Name,
				t.Info.Authors.ToSlice(),
				t.Info.SeverityHolder.Severity))
		}
		s.childExecuter.Execute(t, input)
	}
}

func normalizeAppName(appName string) string {
	if strings.Contains(appName, ":") {
		if parts := strings.Split(appName, ":"); len(parts) == 2 {
			appName = parts[0]
		}
	}
	return strings.ToLower(appName)
}
