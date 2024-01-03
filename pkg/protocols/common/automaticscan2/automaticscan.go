package automaticscan2

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// Service is a service for automatic scan execution
type Service struct {
	opts          protocols.ExecutorOptions
	store         *loader.Store
	engine        *core.Engine
	target        core.InputProvider
	childExecuter *core.ChildExecuter
	techTemplates []*templates.Template

	results      bool
	allTemplates []string
}

// Options contains configuration options for automatic scan service
type Options struct {
	ExecuterOpts protocols.ExecutorOptions
	Store        *loader.Store
	Engine       *core.Engine
	Target       core.InputProvider
}

// New takes options and returns a new automatic scan service
func New(opts Options) (*Service, error) {
	config := config.DefaultConfig
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

	return &Service{
		opts:          opts.ExecuterOpts,
		store:         opts.Store,
		engine:        opts.Engine,
		target:        opts.Target,
		allTemplates:  allTemplates,
		childExecuter: childExecuter,
		techTemplates: tagTemplates,
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
	// Iterate through each target making http request and identifying fingerprints
	inputPool := s.engine.WorkPool().InputPool(types.HTTPProtocol)

	s.target.Scan(func(value *contextargs.MetaInput) bool {
		inputPool.WaitGroup.Add()

		go func(input *contextargs.MetaInput) {
			defer inputPool.WaitGroup.Done()
			s.processInputPair(input)
		}(value)
		return true
	})
	inputPool.WaitGroup.Wait()
}

// processInputPair Retrieve the tags of the website from the tech template and then execute the corresponding template based on the tags.
func (s *Service) processInputPair(input *contextargs.MetaInput) {
	ctxArgs := contextargs.New()
	ctxArgs.MetaInput = input
	inputPool := s.engine.WorkPool().InputPool(types.HTTPProtocol)

	successTags := make([]string, 0)
	successTemplateName := make([]string, 0)
	var mu sync.Mutex
	for _, t := range s.techTemplates {
		inputPool.WaitGroup.Add()
		func(template *templates.Template) {
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
			if len(results) == 0 {
				return
			}
			mu.Lock()
			for _, r := range results {
				successTags = append(successTags, r.Info.Tags.ToSlice()...)
				successTemplateName = append(successTemplateName, r.TemplateID)
			}
			mu.Unlock()
		}(t)
	}
	inputPool.WaitGroup.Wait()

	// Add tags as addition to -as for comprehensive scans. Ref: nuclei/issues/3348
	successTags = append(successTags, s.opts.Options.Tags...)
	uniqueTags := sliceutil.Dedupe(successTags)
	if len(uniqueTags) == 0 {
		return
	}
	var tags []string
	// delete tech tag
	for _, tag := range uniqueTags {
		if tag == "tech" || tag == "waf" || tag == "favicon" {
			continue
		}
		tags = append(tags, tag)
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
	gologger.Info().Msgf("Executing tags (%v) for host %s (%d templates)", strings.Join(tags, ","), input.Input, len(finallyTemplates))
	finallyTemplates, _ = templates.ClusterTemplates(finallyTemplates, s.opts)
	for _, t := range finallyTemplates {
		inputPool.WaitGroup.Add()
		s.opts.Progress.AddToTotal(int64(t.Executer.Requests()))
		if s.opts.Options.VerboseVerbose {
			gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(t.ID,
				t.Info.Name,
				t.Info.Authors.ToSlice(),
				t.Info.SeverityHolder.Severity))
		}
		go func(t *templates.Template) {
			defer inputPool.WaitGroup.Done()
			s.childExecuter.Execute(t, input)
		}(t)
	}
	inputPool.WaitGroup.Wait()
}
