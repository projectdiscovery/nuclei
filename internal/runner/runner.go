package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/atomicboolean"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	input      string
	inputCount int64

	// output is the output file to write if any
	output      *os.File
	outputMutex *sync.Mutex

	tempFile        string
	templatesConfig *nucleiConfig
	// options contains configuration options for runner
	options *Options
	limiter chan struct{}

	// progress tracking
	progress progress.IProgress

	// output coloring
	colorizer   aurora.Aurora
	decolorizer *regexp.Regexp
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		outputMutex: &sync.Mutex{},
		options:     options,
	}

	if err := runner.updateTemplates(); err != nil {
		gologger.Warningf("Could not update templates: %s\n", err)
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

	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)

	if useColor {
		// compile a decolorization regex to cleanup file output messages
		runner.decolorizer = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)
	}

	// If we have stdin, write it to a new file
	if options.Stdin {
		tempInput, err := ioutil.TempFile("", "stdin-input-*")

		if err != nil {
			return nil, err
		}

		if _, err := io.Copy(tempInput, os.Stdin); err != nil {
			return nil, err
		}

		runner.tempFile = tempInput.Name()
		tempInput.Close()
	}
	// If we have single target, write it to a new file
	if options.Target != "" {
		tempInput, err := ioutil.TempFile("", "stdin-input-*")
		if err != nil {
			return nil, err
		}

		fmt.Fprintf(tempInput, "%s\n", options.Target)
		runner.tempFile = tempInput.Name()
		tempInput.Close()
	}

	// Setup input, handle a list of hosts as argument
	var err error

	var input *os.File

	if options.Targets != "" {
		input, err = os.Open(options.Targets)
	} else if options.Stdin || options.Target != "" {
		input, err = os.Open(runner.tempFile)
	}

	if err != nil {
		gologger.Fatalf("Could not open targets file '%s': %s\n", options.Targets, err)
	}

	// Sanitize input and pre-compute total number of targets
	var usedInput = make(map[string]bool)

	dupeCount := 0
	sb := strings.Builder{}
	scanner := bufio.NewScanner(input)
	runner.inputCount = 0

	for scanner.Scan() {
		url := scanner.Text()
		// skip empty lines
		if url == "" {
			continue
		}
		// deduplication
		if _, ok := usedInput[url]; !ok {
			usedInput[url] = true
			runner.inputCount++

			sb.WriteString(url)
			sb.WriteString("\n")
		} else {
			dupeCount++
		}
	}
	input.Close()

	runner.input = sb.String()

	if dupeCount > 0 {
		gologger.Labelf("Supplied input was automatically deduplicated (%d removed).", dupeCount)
	}

	// Create the output file if asked
	if options.Output != "" {
		output, err := os.Create(options.Output)
		if err != nil {
			gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, err)
		}

		runner.output = output
	}

	// Creates the progress tracking object
	runner.progress = progress.NewProgress(runner.options.NoColor, !options.Silent && options.EnableProgressBar)

	runner.limiter = make(chan struct{}, options.Threads)

	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	r.output.Close()
	os.Remove(r.tempFile)
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
		r.colorizer.Bold(templateCount).String(),
		r.colorizer.Bold(templateCount-workflowCount).String(),
		r.colorizer.Bold(workflowCount).String())

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

	var (
		wgtemplates sync.WaitGroup
		results     atomicboolean.AtomBool
	)

	if r.inputCount == 0 {
		gologger.Errorf("Could not find any valid input URLs.")
	} else if totalRequests > 0 || hasWorkflows {
		ctx := context.Background()
		// tracks global progress and captures stdout/stderr until p.Wait finishes
		p := r.progress
		p.InitProgressbar(r.inputCount, templateCount, totalRequests)

		for _, t := range availableTemplates {
			wgtemplates.Add(1)
			go func(template interface{}) {
				defer wgtemplates.Done()
				switch tt := template.(type) {
				case *templates.Template:
					for _, request := range tt.RequestsDNS {
						results.Or(r.processTemplateWithList(ctx, p, tt, request))
					}
					for _, request := range tt.BulkRequestsHTTP {
						results.Or(r.processTemplateWithList(ctx, p, tt, request))
					}
				case *workflows.Workflow:
					workflow := template.(*workflows.Workflow)
					r.processWorkflowWithList(p, workflow)
				}
			}(t)
		}

		wgtemplates.Wait()
		p.Wait()
	}

	if !results.Get() {
		if r.output != nil {
			outputFile := r.output.Name()
			r.output.Close()
			os.Remove(outputFile)
		}

		gologger.Infof("No results found. Happy hacking!")
	}
}
