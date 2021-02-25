package runner

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/internal/collaborator"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalogue"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/clusterer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/issues"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/xid"
	"go.uber.org/atomic"
	"go.uber.org/ratelimit"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	hostMap         *hybrid.HybridMap
	output          output.Writer
	inputCount      int64
	templatesConfig *nucleiConfig
	options         *types.Options
	projectFile     *projectfile.ProjectFile
	catalogue       *catalogue.Catalogue
	progress        *progress.Progress
	colorizer       aurora.Aurora
	issuesClient    *issues.Client
	severityColors  *colorizer.Colorizer
	browser         *engine.Browser
	ratelimiter     ratelimit.Limiter
}

// New creates a new client for running enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	if options.Headless {
		browser, err := engine.New(options)
		if err != nil {
			return nil, err
		}
		runner.browser = browser
	}
	if err := runner.updateTemplates(); err != nil {
		gologger.Warning().Msgf("Could not update templates: %s\n", err)
	}
	// Read nucleiignore file if given a templateconfig
	if runner.templatesConfig != nil {
		runner.readNucleiIgnoreFile()
	}
	runner.catalogue = catalogue.New(runner.options.TemplatesDirectory)

	if options.ReportingConfig != "" {
		if client, err := issues.New(options.ReportingConfig, options.ReportingDB); err != nil {
			gologger.Fatal().Msgf("Could not create issue reporting client: %s\n", err)
		} else {
			runner.issuesClient = client
		}
	}
	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)
	runner.severityColors = colorizer.New(runner.colorizer)

	if options.TemplateList {
		runner.listAvailableTemplates()
		os.Exit(0)
	}

	if (len(options.Templates) == 0 || (options.Targets == "" && !options.Stdin && options.Target == "")) && options.UpdateTemplates {
		os.Exit(0)
	}
	if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err != nil {
		gologger.Fatal().Msgf("Could not create temporary input file: %s\n", err)
	} else {
		runner.hostMap = hm
	}

	runner.inputCount = 0
	dupeCount := 0

	// Handle single target
	if options.Target != "" {
		runner.inputCount++
		// nolint:errcheck // ignoring error
		runner.hostMap.Set(options.Target, nil)
	}

	// Handle stdin
	if options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}
			if _, ok := runner.hostMap.Get(url); ok {
				dupeCount++
				continue
			}
			runner.inputCount++
			// nolint:errcheck // ignoring error
			runner.hostMap.Set(url, nil)
		}
	}

	// Handle taget file
	if options.Targets != "" {
		input, err := os.Open(options.Targets)
		if err != nil {
			gologger.Fatal().Msgf("Could not open targets file '%s': %s\n", options.Targets, err)
		}
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}
			if _, ok := runner.hostMap.Get(url); ok {
				dupeCount++
				continue
			}
			runner.inputCount++
			// nolint:errcheck // ignoring error
			runner.hostMap.Set(url, nil)
		}
		input.Close()
	}

	if dupeCount > 0 {
		gologger.Info().Msgf("Supplied input was automatically deduplicated (%d removed).", dupeCount)
	}

	// Create the output file if asked
	output, err := output.NewStandardWriter(!options.NoColor, options.NoMeta, options.JSON, options.Output, options.TraceLogFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not create output file '%s': %s\n", options.Output, err)
	}
	runner.output = output

	// Creates the progress tracking object
	var progressErr error
	runner.progress, progressErr = progress.NewProgress(options.StatsInterval, options.EnableProgressBar, options.Metrics, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	// create project file if requested or load existing one
	if options.Project {
		var projectFileErr error
		runner.projectFile, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: options.ProjectPath == ""})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	// Enable Polling
	if options.BurpCollaboratorBiid != "" {
		collaborator.DefaultCollaborator.Collab.AddBIID(options.BurpCollaboratorBiid)
	}

	if options.RateLimit > 0 {
		runner.ratelimiter = ratelimit.New(options.RateLimit)
	} else {
		runner.ratelimiter = ratelimit.NewUnlimited()
	}
	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.output != nil {
		r.output.Close()
	}
	r.hostMap.Close()
	if r.projectFile != nil {
		r.projectFile.Close()
	}
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	// resolves input templates definitions and any optional exclusion
	if len(r.options.Templates) == 0 && len(r.options.Tags) > 0 {
		r.options.Templates = append(r.options.Templates, r.options.TemplatesDirectory)
	}
	includedTemplates := r.catalogue.GetTemplatesPath(r.options.Templates)
	excludedTemplates := r.catalogue.GetTemplatesPath(r.options.ExcludedTemplates)
	// defaults to all templates
	allTemplates := includedTemplates

	if len(excludedTemplates) > 0 {
		excludedMap := make(map[string]struct{}, len(excludedTemplates))
		for _, excl := range excludedTemplates {
			excludedMap[excl] = struct{}{}
		}
		// rebuild list with only non-excluded templates
		allTemplates = []string{}

		for _, incl := range includedTemplates {
			if _, found := excludedMap[incl]; !found {
				allTemplates = append(allTemplates, incl)
			} else {
				gologger.Warning().Msgf("Excluding '%s'", incl)
			}
		}
	}

	// pre-parse all the templates, apply filters
	finalTemplates := []*templates.Template{}
	availableTemplates, workflowCount := r.getParsedTemplatesFor(allTemplates, r.options.Severity)

	var unclusteredRequests int64 = 0
	for _, template := range availableTemplates {
		// workflows will dynamically adjust the totals while running, as
		// it can't be know in advance which requests will be called
		if len(template.Workflows) > 0 {
			continue
		}
		unclusteredRequests += int64(template.TotalRequests) * r.inputCount
	}

	originalTemplatesCount := len(availableTemplates)
	clusterCount := 0
	clusters := clusterer.Cluster(availableTemplates)
	for _, cluster := range clusters {
		if len(cluster) > 1 && !r.options.OfflineHTTP {
			executerOpts := protocols.ExecuterOptions{
				Output:       r.output,
				Options:      r.options,
				Progress:     r.progress,
				Catalogue:    r.catalogue,
				RateLimiter:  r.ratelimiter,
				IssuesClient: r.issuesClient,
				Browser:      r.browser,
				ProjectFile:  r.projectFile,
			}
			clusterID := fmt.Sprintf("cluster-%s", xid.New().String())

			finalTemplates = append(finalTemplates, &templates.Template{
				ID:            clusterID,
				RequestsHTTP:  cluster[0].RequestsHTTP,
				Executer:      clusterer.NewExecuter(cluster, &executerOpts),
				TotalRequests: len(cluster[0].RequestsHTTP),
			})
			clusterCount += len(cluster)
		} else {
			for _, item := range cluster {
				finalTemplates = append(finalTemplates, item)
			}
		}
	}

	var totalRequests int64 = 0
	for _, t := range finalTemplates {
		if len(t.Workflows) > 0 {
			continue
		}
		totalRequests += int64(t.TotalRequests) * r.inputCount
	}
	if totalRequests < unclusteredRequests {
		gologger.Info().Msgf("Reduced %d requests to %d (%d templates clustered)", unclusteredRequests, totalRequests, clusterCount)
	}
	templateCount := originalTemplatesCount

	// 0 matches means no templates were found in directory
	if templateCount == 0 {
		gologger.Fatal().Msgf("Error, no templates were found.\n")
	}

	gologger.Info().Msgf("Using %s rules (%s templates, %s workflows)",
		r.colorizer.Bold(templateCount).String(),
		r.colorizer.Bold(templateCount-workflowCount).String(),
		r.colorizer.Bold(workflowCount).String())

	results := &atomic.Bool{}
	wgtemplates := sizedwaitgroup.New(r.options.TemplateThreads)
	// Starts polling or ignore
	collaborator.DefaultCollaborator.Poll()

	// tracks global progress and captures stdout/stderr until p.Wait finishes
	r.progress.Init(r.inputCount, templateCount, totalRequests)

	for _, t := range finalTemplates {
		wgtemplates.Add()
		go func(template *templates.Template) {
			defer wgtemplates.Done()

			if len(template.Workflows) > 0 {
				results.CAS(false, r.processWorkflowWithList(template))
			} else if !r.options.Workflows {
				results.CAS(false, r.processTemplateWithList(template))
			}
		}(t)
	}
	wgtemplates.Wait()
	r.progress.Stop()

	if r.issuesClient != nil {
		r.issuesClient.Close()
	}
	if !results.Load() {
		if r.output != nil {
			r.output.Close()
			os.Remove(r.options.Output)
		}
		gologger.Info().Msgf("No results found. Better luck next time!")
	}

	if r.browser != nil {
		r.browser.Close()
	}
}
