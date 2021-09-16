package runner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/xid"
	"go.uber.org/atomic"
	"go.uber.org/ratelimit"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/clusterer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
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
	addColor        func(severity.Severity) string
	browser         *engine.Browser
	ratelimiter     ratelimit.Limiter
	hostErrors      *hosterrorscache.Cache
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
	if options.Validate {
		parsers.ShouldValidate = true
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

	reportingOptions, err := createReportingOptions(options)
	if err != nil {
		return nil, err
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
	runner.addColor = colorizer.New(runner.colorizer)

	if options.TemplateList {
		runner.listAvailableTemplates()
		os.Exit(0)
	}

	if (len(options.Templates) == 0 || !options.NewTemplates || (options.TargetsFilePath == "" && !options.Stdin && len(options.Targets) == 0)) && options.UpdateTemplates {
		os.Exit(0)
	}
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}
	runner.hostMap = hm

	runner.inputCount = 0
	dupeCount := 0

	// Handle multiple targets
	if len(options.Targets) != 0 {
		for _, target := range options.Targets {
			url := strings.TrimSpace(target)
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

	// Handle target file
	if options.TargetsFilePath != "" {
		input, inputErr := os.Open(options.TargetsFilePath)
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
	outputWriter, err := output.NewStandardWriter(!options.NoColor, options.NoMeta, options.NoTimestamp, options.JSON, options.JSONRequests, options.Output, options.TraceLogFile)
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

	// create project file if requested or load the existing one
	if options.Project {
		var projectFileErr error
		runner.projectFile, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: utils.IsBlank(options.ProjectPath)})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	if !options.NoInteractsh {
		interactshClient, err := interactsh.New(&interactsh.Options{
			ServerURL:      options.InteractshURL,
			Authorization:  options.InteractshToken,
			CacheSize:      int64(options.InteractionsCacheSize),
			Eviction:       time.Duration(options.InteractionsEviction) * time.Second,
			ColldownPeriod: time.Duration(options.InteractionsColldownPeriod) * time.Second,
			PollDuration:   time.Duration(options.InteractionsPollDuration) * time.Second,
			Output:         runner.output,
			IssuesClient:   runner.issuesClient,
			Progress:       runner.progress,
			Debug:          runner.options.Debug,
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

func createReportingOptions(options *types.Options) (*reporting.Options, error) {
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
	return reportingOptions, nil
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

	// If user asked for new templates to be executed, collect the list from the templates' directory.
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

	var cache *hosterrorscache.Cache
	if r.options.MaxHostError > 0 {
		cache = hosterrorscache.New(r.options.MaxHostError, hosterrorscache.DefaultMaxHostsCount).SetVerbose(r.options.Verbose)
	}
	r.hostErrors = cache
	executerOpts := protocols.ExecuterOptions{
		Output:          r.output,
		Options:         r.options,
		Progress:        r.progress,
		Catalog:         r.catalog,
		IssuesClient:    r.issuesClient,
		RateLimiter:     r.ratelimiter,
		Interactsh:      r.interactsh,
		ProjectFile:     r.projectFile,
		Browser:         r.browser,
		HostErrorsCache: cache,
	}

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		return errors.Wrap(err, "Could not create loader.")
	}

	executerOpts.WorkflowLoader = workflowLoader

	loaderConfig := loader.Config{
		Templates:          r.options.Templates,
		Workflows:          r.options.Workflows,
		ExcludeTemplates:   r.options.ExcludedTemplates,
		Tags:               r.options.Tags,
		ExcludeTags:        r.options.ExcludeTags,
		IncludeTemplates:   r.options.IncludeTemplates,
		Authors:            r.options.Author,
		Severities:         r.options.Severities,
		IncludeTags:        r.options.IncludeTags,
		TemplatesDirectory: r.options.TemplatesDirectory,
		Catalog:            r.catalog,
		ExecutorOptions:    executerOpts,
	}
	store, err := loader.New(&loaderConfig)
	if err != nil {
		return errors.Wrap(err, "could not load templates from config")
	}
	store.Load()

	if r.options.Validate {
		if err := store.ValidateTemplates(r.options.Templates, r.options.Workflows); err != nil {
			return err
		}
		if stats.GetValue(parsers.SyntaxErrorStats) == 0 && stats.GetValue(parsers.SyntaxWarningStats) == 0 {
			gologger.Info().Msgf("All templates validated successfully\n")
		} else {
			return errors.New("encountered errors while performing template validation")
		}
		return nil // exit
	}

	// Display stats for any loaded templates' syntax warnings or errors
	stats.Display(parsers.SyntaxWarningStats)
	stats.Display(parsers.SyntaxErrorStats)

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

	if r.templatesConfig != nil && r.templatesConfig.NucleiTemplatesLatestVersion != "" { // TODO extract duplicated logic
		builder.WriteString(" (")

		if r.templatesConfig.TemplateVersion == r.templatesConfig.NucleiTemplatesLatestVersion {
			builder.WriteString(r.colorizer.Green("latest").String())
		} else {
			builder.WriteString(r.colorizer.Red("outdated").String())
		}
		builder.WriteString(")")
	}
	messageStr = builder.String()
	builder.Reset()

	if r.templatesConfig != nil {
		gologger.Info().Msgf("Using Nuclei Templates %s%s", r.templatesConfig.TemplateVersion, messageStr)
	}
	if r.interactsh != nil {
		gologger.Info().Msgf("Using Interactsh Server %s", r.options.InteractshURL)
	}
	if len(store.Templates()) > 0 {
		gologger.Info().Msgf("Templates added in last update: %d", r.countNewTemplates())
		gologger.Info().Msgf("Templates loaded for scan: %d", len(store.Templates()))
	}
	if len(store.Workflows()) > 0 {
		gologger.Info().Msgf("Workflows loaded for scan: %d", len(store.Workflows()))
	}

	// pre-parse all the templates, apply filters
	finalTemplates := []*templates.Template{}

	var unclusteredRequests int64
	for _, template := range store.Templates() {
		// workflows will dynamically adjust the totals while running, as
		// it can't be known in advance which requests will be called
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
		templatesMap[v.Path] = v
	}
	originalTemplatesCount := len(store.Templates())
	clusterCount := 0
	clusters := clusterer.Cluster(templatesMap)
	for _, cluster := range clusters {
		if len(cluster) > 1 && !r.options.OfflineHTTP {
			executerOpts := protocols.ExecuterOptions{
				Output:          r.output,
				Options:         r.options,
				Progress:        r.progress,
				Catalog:         r.catalog,
				RateLimiter:     r.ratelimiter,
				IssuesClient:    r.issuesClient,
				Browser:         r.browser,
				ProjectFile:     r.projectFile,
				Interactsh:      r.interactsh,
				HostErrorsCache: cache,
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
		return errors.New("no valid templates were found")
	}

	/*
		TODO does it make sense to run the logic below if there are no targets specified?
		Can we safely assume the user is just experimenting with the template/workflow filters before running them?
	*/

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
	if r.templatesConfig == nil {
		return nil, nil
	}
	additionsFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
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

// countNewTemplates returns the number of newly added templates
func (r *Runner) countNewTemplates() int {
	if r.templatesConfig == nil {
		return 0
	}
	additionsFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
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
