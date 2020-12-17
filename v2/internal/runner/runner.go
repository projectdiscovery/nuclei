package runner

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/internal/bufwriter"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/internal/tracelog"
	"github.com/projectdiscovery/nuclei/v2/pkg/atomicboolean"
	"github.com/projectdiscovery/nuclei/v2/pkg/collaborator"
	"github.com/projectdiscovery/nuclei/v2/pkg/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	inputCount int64

	traceLog tracelog.Log

	// output is the output file to write if any
	output *bufwriter.Writer

	templatesConfig *nucleiConfig
	// options contains configuration options for runner
	options *Options

	pf *projectfile.ProjectFile

	// progress tracking
	progress *progress.Progress

	// output coloring
	colorizer   colorizer.NucleiColorizer
	decolorizer *regexp.Regexp

	// rate limiter
	ratelimiter ratelimit.Limiter

	// input deduplication
	hm     *hybrid.HybridMap
	dialer *fastdialer.Dialer
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		traceLog: &tracelog.NoopLogger{},
		options:  options,
	}
	if options.TraceLogFile != "" {
		fileLog, err := tracelog.NewFileLogger(options.TraceLogFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not create file trace logger")
		}
		runner.traceLog = fileLog
	}

	if err := runner.updateTemplates(); err != nil {
		gologger.Labelf("Could not update templates: %s\n", err)
	}

	// output coloring
	useColor := !options.NoColor
	runner.colorizer = *colorizer.NewNucleiColorizer(aurora.NewAurora(useColor))

	if useColor {
		// compile a decolorization regex to cleanup file output messages
		runner.decolorizer = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)
	}

	if options.TemplateList {
		runner.listAvailableTemplates()
		os.Exit(0)
	}

	if (len(options.Templates) == 0 || (options.Targets == "" && !options.Stdin && options.Target == "")) && options.UpdateTemplates {
		os.Exit(0)
	}
	// Read nucleiignore file if given a templateconfig
	if runner.templatesConfig != nil {
		runner.readNucleiIgnoreFile()
	}

	if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err != nil {
		gologger.Fatalf("Could not create temporary input file: %s\n", err)
	} else {
		runner.hm = hm
	}

	runner.inputCount = 0
	dupeCount := 0

	// Handle single target
	if options.Target != "" {
		runner.inputCount++
		// nolint:errcheck // ignoring error
		runner.hm.Set(options.Target, nil)
	}

	// Handle stdin
	if options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			// skip empty lines
			if url == "" {
				continue
			}

			// skip dupes
			if _, ok := runner.hm.Get(url); ok {
				dupeCount++
				continue
			}

			runner.inputCount++
			// nolint:errcheck // ignoring error
			runner.hm.Set(url, nil)
		}
	}

	// Handle taget file
	if options.Targets != "" {
		input, err := os.Open(options.Targets)
		if err != nil {
			gologger.Fatalf("Could not open targets file '%s': %s\n", options.Targets, err)
		}
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			// skip empty lines
			if url == "" {
				continue
			}

			// skip dupes
			if _, ok := runner.hm.Get(url); ok {
				dupeCount++
				continue
			}

			runner.inputCount++
			// nolint:errcheck // ignoring error
			runner.hm.Set(url, nil)
		}
		input.Close()
	}

	if dupeCount > 0 {
		gologger.Labelf("Supplied input was automatically deduplicated (%d removed).", dupeCount)
	}

	// Create the output file if asked
	if options.Output != "" {
		output, errBufWriter := bufwriter.New(options.Output)
		if errBufWriter != nil {
			gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, errBufWriter)
		}
		runner.output = output
	}

	// Creates the progress tracking object
	var progressErr error
	runner.progress, progressErr = progress.NewProgress(options.EnableProgressBar, options.Metrics, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	// create project file if requested or load existing one
	if options.Project {
		var projectFileErr error
		runner.pf, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: options.ProjectPath == ""})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	// Enable Polling
	if options.BurpCollaboratorBiid != "" {
		collaborator.DefaultCollaborator.Collab.AddBIID(options.BurpCollaboratorBiid)
	}

	// Create Dialer
	var err error
	runner.dialer, err = fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return nil, err
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
	r.hm.Close()
	if r.pf != nil {
		r.pf.Close()
	}
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	// resolves input templates definitions and any optional exclusion
	includedTemplates := r.getTemplatesFor(r.options.Templates)
	excludedTemplates := r.getTemplatesFor(r.options.ExcludedTemplates)
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
				gologger.Warningf("Excluding '%s'", incl)
			}
		}
	}

	// pre-parse all the templates, apply filters
	availableTemplates, workflowCount := r.getParsedTemplatesFor(allTemplates, r.options.Severity)
	templateCount := len(availableTemplates)
	hasWorkflows := workflowCount > 0

	// 0 matches means no templates were found in directory
	if templateCount == 0 {
		gologger.Fatalf("Error, no templates were found.\n")
	}

	gologger.Infof("Using %s rules (%s templates, %s workflows)",
		r.colorizer.Colorizer.Bold(templateCount).String(),
		r.colorizer.Colorizer.Bold(templateCount-workflowCount).String(),
		r.colorizer.Colorizer.Bold(workflowCount).String())

	// precompute total request count
	var totalRequests int64 = 0

	for _, t := range availableTemplates {
		switch av := t.(type) {
		case *templates.Template:
			totalRequests += (av.GetHTTPRequestCount() + av.GetDNSRequestCount()) * r.inputCount
		case *workflows.Workflow:
			// workflows will dynamically adjust the totals while running, as
			// it can't be know in advance which requests will be called
		} // nolint:wsl // comment
	}

	results := atomicboolean.New()
	wgtemplates := sizedwaitgroup.New(r.options.TemplateThreads)
	// Starts polling or ignore
	collaborator.DefaultCollaborator.Poll()

	if r.inputCount == 0 {
		gologger.Errorf("Could not find any valid input URLs.")
	} else if totalRequests > 0 || hasWorkflows {
		// tracks global progress and captures stdout/stderr until p.Wait finishes
		p := r.progress
		p.Init(r.inputCount, templateCount, totalRequests)

		for _, t := range availableTemplates {
			wgtemplates.Add()
			go func(template interface{}) {
				defer wgtemplates.Done()
				switch tt := template.(type) {
				case *templates.Template:
					for _, request := range tt.RequestsDNS {
						results.Or(r.processTemplateWithList(p, tt, request))
					}
					for _, request := range tt.BulkRequestsHTTP {
						results.Or(r.processTemplateWithList(p, tt, request))
					}
				case *workflows.Workflow:
					results.Or(r.processWorkflowWithList(p, template.(*workflows.Workflow)))
				}
			}(t)
		}

		wgtemplates.Wait()
		p.Stop()
	}

	if !results.Get() {
		if r.output != nil {
			r.output.Close()
			os.Remove(r.options.Output)
		}

		gologger.Infof("No results found. Happy hacking!")
	}
}
