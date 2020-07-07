package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/d5/tengo/v2"
	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/executor"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	input 		*os.File
	inputCount	int64

	// output is the output file to write if any
	output      *os.File
	outputMutex *sync.Mutex

	tempFile        string
	templatesConfig *nucleiConfig
	// options contains configuration options for runner
	options *Options
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		outputMutex: &sync.Mutex{},
		options:     options,
	}

	if err := runner.updateTemplates(); err != nil {
		return nil, err
	}
	if (options.Templates == "" || (options.Targets == "" && !options.Stdin && options.Target == "")) && options.UpdateTemplates {
		os.Exit(0)
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
		tempInput.WriteString(options.Target)
		runner.tempFile = tempInput.Name()
		tempInput.Close()
	}

	// Setup input, handle a list of hosts as argument
	var err error
	if options.Targets != "" {
		runner.input, err = os.Open(options.Targets)
	} else if options.Stdin || options.Target != "" {
		runner.input, err = os.Open(runner.tempFile)
	}
	if err != nil {
		gologger.Fatalf("Could not open targets file '%s': %s\n", options.Targets, err)
	}

	// Precompute total number of targets
	scanner := bufio.NewScanner(runner.input)
	runner.inputCount = 0
	for scanner.Scan() {
		runner.inputCount++
	}
	runner.input.Seek(0,0)

	// Create the output file if asked
	if options.Output != "" {
		output, err := os.Create(options.Output)
		if err != nil {
			gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, err)
		}
		runner.output = output
	}
	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	r.output.Close()
	r.input.Close()
	os.Remove(r.tempFile)
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	var err error

	// Check if the template is an absolute path or relative path.
	// If the path is absolute, use it. Otherwise,
	if r.isRelative(r.options.Templates) {
		newPath, err := r.resolvePath(r.options.Templates)
		if err != nil {
			gologger.Errorf("Could not find template file '%s': %s\n", r.options.Templates, err)
			return
		}
		r.options.Templates = newPath
	}

	// Single yaml provided
	if strings.HasSuffix(r.options.Templates, ".yaml") {
		t, err := r.parse(r.options.Templates)

		// track progress
		p := progress.NewProgress(nil)

		switch t.(type) {
		case *templates.Template:
			var results bool
			template := t.(*templates.Template)

			p.SetupProgressBar(template.ID, r.inputCount * template.GetHTTPRequestsCount())

			// process http requests
			for _, request := range template.RequestsHTTP {
				results = r.processTemplateWithList(p, template, request)
			}

			// process dns requests
			for _, request := range template.RequestsDNS {
				dnsResults := r.processTemplateWithList(p, template, request)
				if !results {
					results = dnsResults
				}
			}

			p.Wait()

			if !results {
				if r.output != nil {
					outputFile := r.output.Name()
					r.output.Close()
					os.Remove(outputFile)
				}
				gologger.Infof("No results found for the template. Happy hacking!")
			}
		case *workflows.Workflow:
			workflow := t.(*workflows.Workflow)
			r.ProcessWorkflowWithList(workflow)
		default:
			gologger.Errorf("Could not parse file '%s': %s\n", r.options.Templates, err)
		}
		return
	}

	// If the template passed is a directory
	matches := []string{}

	// Recursively walk down the Templates directory and run all the template file checks
	err = godirwalk.Walk(r.options.Templates, &godirwalk.Options{
		Callback: func(path string, d *godirwalk.Dirent) error {
			if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
				matches = append(matches, path)
			}
			return nil
		},
		ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
		Unsorted: true,
	})
	if err != nil {
		gologger.Fatalf("Could not find templates in directory '%s': %s\n", r.options.Templates, err)
	}
	// 0 matches means no templates were found in directory
	if len(matches) == 0 {
		gologger.Fatalf("Error, no templates found in directory: '%s'\n", r.options.Templates)
	}

	// track progress
	p := progress.NewProgress(nil)

	var results bool
	for _, match := range matches {
		t, err := r.parse(match)
		switch t.(type) {
		case *templates.Template:
			template := t.(*templates.Template)
			for _, request := range template.RequestsDNS {
				dnsResults := r.processTemplateWithList(p, template, request)
				if dnsResults {
					results = dnsResults
				}
			}

			p.SetupProgressBar(template.ID, r.inputCount * template.GetHTTPRequestsCount())

			for _, request := range template.RequestsHTTP {
				httpResults := r.processTemplateWithList(p, template, request)
				if httpResults {
					results = httpResults
				}
			}

		case *workflows.Workflow:
			workflow := t.(*workflows.Workflow)
			r.ProcessWorkflowWithList(workflow)
		default:
			p.StartStdCapture()
			gologger.Errorf("Could not parse file '%s': %s\n", r.options.Templates, err)
			p.StopStdCaptureAndShow()
		}
	}
	p.Wait()

	if !results {
		if r.output != nil {
			outputFile := r.output.Name()
			r.output.Close()
			os.Remove(outputFile)
		}
		//p.StartStdCapture()
		gologger.Infof("No results found for the template. Happy hacking!")
		//p.StopStdCaptureAndShow()
	}

	return
}

// processTemplateWithList processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplateWithList(p *progress.Progress, template *templates.Template, request interface{}) bool {
	// Display the message for the template
	message := fmt.Sprintf("[%s] Loaded template %s (@%s)", template.ID, template.Info.Name, template.Info.Author)
	if template.Info.Severity != "" {
		message += " [" + template.Info.Severity + "]"
	}
	p.StartStdCapture()
	gologger.Infof("%s\n", message)
	p.StopStdCaptureAndShow()

	var writer *bufio.Writer
	if r.output != nil {
		writer = bufio.NewWriter(r.output)
		defer writer.Flush()
	}

	var httpExecutor *executor.HTTPExecutor
	var dnsExecutor *executor.DNSExecutor
	var err error

	// Create an executor based on the request type.
	switch value := request.(type) {
	case *requests.DNSRequest:
		dnsExecutor = executor.NewDNSExecutor(&executor.DNSOptions{
			Debug:      r.options.Debug,
			Template:   template,
			DNSRequest: value,
			Writer:     writer,
			JSON:       r.options.JSON,
		})
	case *requests.HTTPRequest:
		httpExecutor, err = executor.NewHTTPExecutor(&executor.HTTPOptions{
			Debug:         r.options.Debug,
			Template:      template,
			HTTPRequest:   value,
			Writer:        writer,
			Timeout:       r.options.Timeout,
			Retries:       r.options.Retries,
			ProxyURL:      r.options.ProxyURL,
			ProxySocksURL: r.options.ProxySocksURL,
			CustomHeaders: r.options.CustomHeaders,
			JSON:          r.options.JSON,
		})
	}
	if err != nil {
		p.StartStdCapture()
		gologger.Warningf("Could not create http client: %s\n", err)
		p.StopStdCaptureAndShow()
		return false
	}

	limiter := make(chan struct{}, r.options.Threads)
	wg := &sync.WaitGroup{}

	r.input.Seek(0, 0)
	scanner := bufio.NewScanner(r.input)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		limiter <- struct{}{}
		wg.Add(1)

		go func(URL string) {
			var err error

			if httpExecutor != nil {
				err = httpExecutor.ExecuteHTTP(p, URL)
			}
			if dnsExecutor != nil {
				err = dnsExecutor.ExecuteDNS(URL)
			}
			if err != nil {
				p.StartStdCapture()
				gologger.Warningf("Could not execute step: %s\n", err)
				p.StopStdCaptureAndShow()
			}
			<-limiter
			wg.Done()
		}(text)
	}
	close(limiter)

	wg.Wait()

	// See if we got any results from the executors
	var results bool
	if httpExecutor != nil {
		results = httpExecutor.GotResults()
	}
	if dnsExecutor != nil {
		if !results {
			results = dnsExecutor.GotResults()
		}
	}
	return results
}

// ProcessWorkflowWithList coming from stdin or list of targets
func (r *Runner) ProcessWorkflowWithList(workflow *workflows.Workflow) {
	r.input.Seek(0, 0)
	scanner := bufio.NewScanner(r.input)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		if err := r.ProcessWorkflow(workflow, text); err != nil {
			gologger.Warningf("Could not run workflow for %s: %s\n", text, err)
		}
	}
}

// ProcessWorkflow towards an URL
func (r *Runner) ProcessWorkflow(workflow *workflows.Workflow, URL string) error {
	script := tengo.NewScript([]byte(workflow.Logic))

	for name, value := range workflow.Variables {
		var writer *bufio.Writer
		if r.output != nil {
			writer = bufio.NewWriter(r.output)
			defer writer.Flush()
		}

		// Check if the template is an absolute path or relative path.
		// If the path is absolute, use it. Otherwise,
		if r.isRelative(value) {
			newPath, err := r.resolvePath(value)
			if err != nil {
				return err
			}
			value = newPath
		}

		// Single yaml provided
		var templatesList []*workflows.Template
		if strings.HasSuffix(value, ".yaml") {
			t, err := templates.Parse(value)
			if err != nil {
				return err
			}
			template := &workflows.Template{}
			if len(t.RequestsHTTP) > 0 {
				template.HTTPOptions = &executor.HTTPOptions{
					Debug:         r.options.Debug,
					Writer:        writer,
					Template:      t,
					Timeout:       r.options.Timeout,
					Retries:       r.options.Retries,
					ProxyURL:      r.options.ProxyURL,
					ProxySocksURL: r.options.ProxySocksURL,
					CustomHeaders: r.options.CustomHeaders,
				}
			} else if len(t.RequestsDNS) > 0 {
				template.DNSOptions = &executor.DNSOptions{
					Debug:    r.options.Debug,
					Template: t,
					Writer:   writer,
				}
			}
			if template.DNSOptions != nil || template.HTTPOptions != nil {
				templatesList = append(templatesList, template)
			}
		} else {
			matches := []string{}

			err := godirwalk.Walk(value, &godirwalk.Options{
				Callback: func(path string, d *godirwalk.Dirent) error {
					if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
						matches = append(matches, path)
					}
					return nil
				},
				ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
					return godirwalk.SkipNode
				},
				Unsorted: true,
			})
			if err != nil {
				return err
			}
			// 0 matches means no templates were found in directory
			if len(matches) == 0 {
				return errors.New("no match found in the directory")
			}

			for _, match := range matches {
				t, err := templates.Parse(match)
				if err != nil {
					return err
				}
				template := &workflows.Template{}
				if len(t.RequestsHTTP) > 0 {
					template.HTTPOptions = &executor.HTTPOptions{
						Debug:         r.options.Debug,
						Writer:        writer,
						Template:      t,
						Timeout:       r.options.Timeout,
						Retries:       r.options.Retries,
						ProxyURL:      r.options.ProxyURL,
						ProxySocksURL: r.options.ProxySocksURL,
						CustomHeaders: r.options.CustomHeaders,
					}
				} else if len(t.RequestsDNS) > 0 {
					template.DNSOptions = &executor.DNSOptions{
						Debug:    r.options.Debug,
						Template: t,
						Writer:   writer,
					}
				}
				if template.DNSOptions != nil || template.HTTPOptions != nil {
					templatesList = append(templatesList, template)
				}
			}
		}

		script.Add(name, &workflows.NucleiVar{Templates: templatesList, URL: URL})
	}

	_, err := script.RunContext(context.Background())
	if err != nil {
		gologger.Errorf("Could not execute workflow '%s': %s\n", workflow.ID, err)
		return err
	}
	return nil
}

func (r *Runner) parse(file string) (interface{}, error) {
	// check if it's a template
	template, errTemplate := templates.Parse(file)
	if errTemplate == nil {
		return template, nil
	}

	// check if it's a workflow
	workflow, errWorkflow := workflows.Parse(file)
	if errWorkflow == nil {
		return workflow, nil
	}

	if errTemplate != nil {
		return nil, errTemplate
	}
	if errWorkflow != nil {
		return nil, errWorkflow
	}
	return nil, errors.New("unknown error occured")
}
