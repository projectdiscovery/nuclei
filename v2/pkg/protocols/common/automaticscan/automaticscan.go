package automaticscan

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/retryablehttp-go"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"gopkg.in/yaml.v2"
)

// Service is a service for automatic automatic scan execution
type Service struct {
	opts          protocols.ExecuterOptions
	store         *loader.Store
	engine        *core.Engine
	target        core.InputProvider
	wappalyzer    *wappalyzer.Wappalyze
	childExecuter *core.ChildExecuter
	httpclient    *retryablehttp.Client

	results            bool
	allTemplates       []string
	technologyMappings map[string]string
}

// Options contains configuration options for automatic scan service
type Options struct {
	ExecuterOpts protocols.ExecuterOptions
	Store        *loader.Store
	Engine       *core.Engine
	Target       core.InputProvider
}

const mappingFilename = "wappalyzer-mapping.yml"

// New takes options and returns a new smart workflow service
func New(opts Options) (*Service, error) {
	wappalyzer, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	var mappingData map[string]string
	config, err := config.ReadConfiguration()
	if err == nil {
		mappingFile := filepath.Join(config.TemplatesDirectory, mappingFilename)
		if file, err := os.Open(mappingFile); err == nil {
			_ = yaml.NewDecoder(file).Decode(&mappingData)
			file.Close()
		}
	}
	if opts.ExecuterOpts.Options.Verbose {
		gologger.Verbose().Msgf("Normalized mapping (%d): %v\n", len(mappingData), mappingData)
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
	childExecuter := opts.Engine.ChildExecuter()

	httpclient, err := httpclientpool.Get(opts.ExecuterOpts.Options, &httpclientpool.Configuration{
		Connection: &httpclientpool.ConnectionConfiguration{DisableKeepAlive: true},
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

// Execute performs the execution of smart workflows on provided input
func (s *Service) Execute() {
	if err := s.executeWappalyzerTechDetection(); err != nil {
		gologger.Error().Msgf("Could not execute wappalyzer based detection: %s", err)
	}
}

var (
	defaultTemplatesDirectories = []string{"cves/", "default-logins/", "dns/", "exposures/", "miscellaneous/", "misconfiguration/", "network/", "takeovers/", "vulnerabilities/"}
)

const maxDefaultBody = 2 * 1024 * 1024

// executeWappalyzerTechDetection implements the logic to run the wappalyzer
// technologies detection on inputs which returns tech.
//
// The returned tags are then used for further execution.
func (s *Service) executeWappalyzerTechDetection() error {
	gologger.Info().Msgf("Executing wappalyzer based tech detection on input urls")

	// Iterate through each target making http request and identifying fingerprints
	inputPool := s.engine.WorkPool().InputPool(types.HTTPProtocol)

	s.target.Scan(func(value string) {
		inputPool.WaitGroup.Add()

		go func(input string) {
			defer inputPool.WaitGroup.Done()
			s.processWappalyzerInputPair(input)
		}(value)
	})
	inputPool.WaitGroup.Wait()
	return nil
}

func (s *Service) processWappalyzerInputPair(input string) {
	req, err := retryablehttp.NewRequest(http.MethodGet, input, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := s.httpclient.Do(req)
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
	normalized := make(map[string]struct{})
	for k := range fingerprints {
		normalized[strings.ToLower(k)] = struct{}{}
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
	if len(items) == 0 {
		return
	}
	uniqueTags := uniqueSlice(items)

	templatesList := s.store.LoadTemplatesWithTags(s.allTemplates, uniqueTags)
	gologger.Info().Msgf("Executing tags (%v) for host %s (%d templates)", strings.Join(uniqueTags, ","), input, len(templatesList))
	for _, t := range templatesList {
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

func uniqueSlice(slice []string) []string {
	data := make(map[string]struct{}, len(slice))
	for _, item := range slice {
		if _, ok := data[item]; !ok {
			data[item] = struct{}{}
		}
	}
	finalSlice := make([]string, 0, len(data))
	for item := range data {
		finalSlice = append(finalSlice, item)
	}
	return finalSlice
}
