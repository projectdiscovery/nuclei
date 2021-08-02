package runner

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/clusterer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/xid"
	"go.uber.org/atomic"
	"go.uber.org/ratelimit"
	"gopkg.in/yaml.v2"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	hostMap         *hybrid.HybridMap
	output          output.Writer
	interactsh      *interactsh.Client
	inputCount      int64
	templatesConfig *config.Config
	options         *types.Options
	projectFile     *projectfile.ProjectFile
	catalog         *catalog.Catalog
	progress        progress.Progress
	colorizer       aurora.Aurora
	issuesClient    *reporting.Client
	severityColors  *colorizer.Colorizer
	browser         *engine.Browser
	ratelimiter     ratelimit.Limiter
}

// New creates a new client for running enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	if options.UpdateNuclei {
		if err := updateNucleiVersionToLatest(runner.options.Verbose); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err := runner.updateTemplates(); err != nil {
		gologger.Warning().Msgf("Could not update templates: %s\n", err)
	}
	if options.Headless {
		browser, err := engine.New(options)
		if err != nil {
			return nil, err
		}
		runner.browser = browser
	}

	runner.catalog = catalog.New(runner.options.TemplatesDirectory)
	var reportingOptions *reporting.Options
	if options.ReportingConfig != "" {
		file, err := os.Open(options.ReportingConfig)
		if err != nil {
			return nil, errors.Wrap(err, "could not open reporting config file")
		}

		reportingOptions = &reporting.Options{}
		if parseErr := yaml.NewDecoder(file).Decode(reportingOptions); parseErr != nil {
			file.Close()
			return nil, errors.Wrap(parseErr, "could not parse reporting config file")
		}
		file.Close()
	}
	if options.DiskExportDirectory != "" {
		if reportingOptions != nil {
			reportingOptions.DiskExporter = &disk.Options{Directory: options.DiskExportDirectory}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.DiskExporter = &disk.Options{Directory: options.DiskExportDirectory}
		}
	}
	if options.SarifExport != "" {
		if reportingOptions != nil {
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		}
	}
	if reportingOptions != nil {
		client, err := reporting.New(reportingOptions, options.ReportingDB)
		if err != nil {
			return nil, errors.Wrap(err, "could not create issue reporting client")
		}
		runner.issuesClient = client
	}

	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)
	runner.severityColors = colorizer.New(runner.colorizer)

	if options.TemplateList {
		runner.listAvailableTemplates()
		os.Exit(0)
	}

	if (len(options.Templates) == 0 || !options.NewTemplates || (options.Targets == "" && !options.Stdin && options.Target == "")) && options.UpdateTemplates {
		os.Exit(0)
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}
	runner.hostMap = hm

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
		input, inputErr := os.Open(options.Targets)
		if inputErr != nil {
			return nil, errors.Wrap(inputErr, "could not open targets file")
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
	outputWriter, err := output.NewStandardWriter(!options.NoColor, options.NoMeta, options.JSON, options.Output, options.TraceLogFile)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}
	runner.output = outputWriter

	if options.JSON && options.EnableProgressBar {
		options.StatsJSON = true
	}
	if options.StatsJSON {
		options.EnableProgressBar = true
	}
	// Creates the progress tracking object
	var progressErr error
	runner.progress, progressErr = progress.NewStatsTicker(options.StatsInterval, options.EnableProgressBar, options.StatsJSON, options.Metrics, options.MetricsPort)
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

	if !options.NoInteractsh {
		interactshClient, err := interactsh.New(&interactsh.Options{
			ServerURL:      options.InteractshURL,
			CacheSize:      int64(options.InteractionsCacheSize),
			Eviction:       time.Duration(options.InteractionsEviction) * time.Second,
			ColldownPeriod: time.Duration(options.InteractionsColldownPeriod) * time.Second,
			PollDuration:   time.Duration(options.InteractionsPollDuration) * time.Second,
			Output:         runner.output,
			IssuesClient:   runner.issuesClient,
			Progress:       runner.progress,
		})
		if err != nil {
			gologger.Error().Msgf("Could not create interactsh client: %s", err)
		} else {
			runner.interactsh = interactshClient
		}
	}

	if options.RateLimitMinute > 0 {
		runner.ratelimiter = ratelimit.New(options.RateLimitMinute, ratelimit.Per(60*time.Second))
	} else if options.RateLimit > 0 {
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
	protocolinit.Close()
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() error {
	defer r.Close()

	// If user asked for new templates to be executed, collect the list from template directory.
	if r.options.NewTemplates {
		templatesLoaded, err := r.readNewTemplatesFile()
		if err != nil {
			return errors.Wrap(err, "could not get newly added templates")
		}
		r.options.Templates = append(r.options.Templates, templatesLoaded...)
	}
	ignoreFile := config.ReadIgnoreFile()
	r.options.ExcludeTags = append(r.options.ExcludeTags, ignoreFile.Tags...)
	r.options.ExcludedTemplates = append(r.options.ExcludedTemplates, ignoreFile.Files...)

	executerOpts := protocols.ExecuterOptions{
		Output:       r.output,
		Options:      r.options,
		Progress:     r.progress,
		Catalog:      r.catalog,
		IssuesClient: r.issuesClient,
		RateLimiter:  r.ratelimiter,
		Interactsh:   r.interactsh,
		ProjectFile:  r.projectFile,
		Browser:      r.browser,
	}
	loaderConfig := loader.Config{
		Templates:          r.options.Templates,
		Workflows:          r.options.Workflows,
		ExcludeTemplates:   r.options.ExcludedTemplates,
		Tags:               r.options.Tags,
		ExcludeTags:        r.options.ExcludeTags,
		IncludeTemplates:   r.options.IncludeTemplates,
		Authors:            r.options.Author,
		Severities:         r.options.Severity,
		IncludeTags:        r.options.IncludeTags,
		TemplatesDirectory: r.options.TemplatesDirectory,
		Catalog:            r.catalog,
		ExecutorOptions:    executerOpts,
	}
	store, err := loader.New(&loaderConfig)
	if err != nil {
		return errors.Wrap(err, "could not load templates from config")
	}
	if r.options.Validate {
		if !store.ValidateTemplates(r.options.Templates, r.options.Workflows) {
			return errors.New("an error occurred during templates validation")
		}
		gologger.Info().Msgf("All templates validated successfully\n")
		return nil // exit
	}
	store.Load()

	builder := &strings.Builder{}
	if r.templatesConfig != nil && r.templatesConfig.NucleiLatestVersion != "" {
		builder.WriteString(" (")

		if strings.Contains(config.Version, "-dev") {
			builder.WriteString(r.colorizer.Blue("development").String())
		} else if config.Version == r.templatesConfig.NucleiLatestVersion {
			builder.WriteString(r.colorizer.Green("latest").String())
		} else {
			builder.WriteString(r.colorizer.Red("outdated").String())
		}
		builder.WriteString(")")
	}
	messageStr := builder.String()
	builder.Reset()

	gologger.Info().Msgf("Using Nuclei Engine %s%s", config.Version, messageStr)

	if r.templatesConfig != nil && r.templatesConfig.NucleiTemplatesLatestVersion != "" {
		builder.WriteString(" (")

		if r.templatesConfig.CurrentVersion == r.templatesConfig.NucleiTemplatesLatestVersion {
			builder.WriteString(r.colorizer.Green("latest").String())
		} else {
			builder.WriteString(r.colorizer.Red("outdated").String())
		}
		builder.WriteString(")")
	}
	messageStr = builder.String()
	builder.Reset()

	gologger.Info().Msgf("Using Nuclei Templates %s%s", r.templatesConfig.CurrentVersion, messageStr)

	if r.interactsh != nil {
		gologger.Info().Msgf("Using Interactsh Server %s", r.options.InteractshURL)
	}
	if len(store.Templates()) > 0 {
		gologger.Info().Msgf("Templates loaded: %d (New: %d)", len(store.Templates()), r.countNewTemplates())
	}
	if len(store.Workflows()) > 0 {
		gologger.Info().Msgf("Workflows loaded: %d", len(store.Workflows()))
	}

	// pre-parse all the templates, apply filters
	finalTemplates := []*templates.Template{}

	var unclusteredRequests int64
	for _, template := range store.Templates() {
		// workflows will dynamically adjust the totals while running, as
		// it can't be know in advance which requests will be called
		if len(template.Workflows) > 0 {
			continue
		}
		unclusteredRequests += int64(template.TotalRequests) * r.inputCount
	}

	if r.options.VerboseVerbose {
		for _, template := range store.Templates() {
			r.logAvailableTemplate(template.Path)
		}
		for _, template := range store.Workflows() {
			r.logAvailableTemplate(template.Path)
		}
	}
	templatesMap := make(map[string]*templates.Template)
	for _, v := range store.Templates() {
		templatesMap[v.ID] = v
	}
	originalTemplatesCount := len(store.Templates())
	clusterCount := 0
	clusters := clusterer.Cluster(templatesMap)
	for _, cluster := range clusters {
		if len(cluster) > 1 && !r.options.OfflineHTTP {
			executerOpts := protocols.ExecuterOptions{
				Output:       r.output,
				Options:      r.options,
				Progress:     r.progress,
				Catalog:      r.catalog,
				RateLimiter:  r.ratelimiter,
				IssuesClient: r.issuesClient,
				Browser:      r.browser,
				ProjectFile:  r.projectFile,
				Interactsh:   r.interactsh,
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
			finalTemplates = append(finalTemplates, cluster...)
		}
	}
	finalTemplates = append(finalTemplates, store.Workflows()...)

	var totalRequests int64
	for _, t := range finalTemplates {
		if len(t.Workflows) > 0 {
			continue
		}
		totalRequests += int64(t.TotalRequests) * r.inputCount
	}
	if totalRequests < unclusteredRequests {
		gologger.Info().Msgf("Templates clustered: %d (Reduced %d HTTP Requests)", clusterCount, unclusteredRequests-totalRequests)
	}
	workflowCount := len(store.Workflows())
	templateCount := originalTemplatesCount + workflowCount

	// 0 matches means no templates were found in directory
	if templateCount == 0 {
		return errors.New("no templates were found")
	}

	results := &atomic.Bool{}
	wgtemplates := sizedwaitgroup.New(r.options.TemplateThreads)

	// tracks global progress and captures stdout/stderr until p.Wait finishes
	r.progress.Init(r.inputCount, templateCount, totalRequests)

	for _, t := range finalTemplates {
		wgtemplates.Add()
		go func(template *templates.Template) {
			defer wgtemplates.Done()

			if len(template.Workflows) > 0 {
				results.CAS(false, r.processWorkflowWithList(template))
			} else {
				results.CAS(false, r.processTemplateWithList(template))
			}
		}(t)
	}
	wgtemplates.Wait()

	if r.interactsh != nil {
		matched := r.interactsh.Close()
		if matched {
			results.CAS(false, true)
		}
	}
	r.progress.Stop()

	if r.issuesClient != nil {
		r.issuesClient.Close()
	}
	if !results.Load() {
		gologger.Info().Msgf("No results found. Better luck next time!")
	}
	if r.browser != nil {
		r.browser.Close()
	}
	return nil
}

// readNewTemplatesFile reads newly added templates from directory if it exists
func (r *Runner) readNewTemplatesFile() ([]string, error) {
	additionsFile := path.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	file, err := os.Open(additionsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	templatesList := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		templatesList = append(templatesList, text)
	}
	return templatesList, nil
}

// readNewTemplatesFile reads newly added templates from directory if it exists
func (r *Runner) countNewTemplates() int {
	additionsFile := path.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	file, err := os.Open(additionsFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		count++
	}
	return count
}
