package runner

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/pkg/executor"
	"github.com/projectdiscovery/nuclei/pkg/requests"
	"github.com/projectdiscovery/nuclei/pkg/templates"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	// output is the output file to write if any
	output      *os.File
	outputMutex *sync.Mutex

	tempFile string
	// options contains configuration options for runner
	options *Options
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		outputMutex: &sync.Mutex{},
		options:     options,
	}

	// If we have stdin, write it to a new file
	if options.Stdin {
		tempInput, err := ioutil.TempFile("", "stdin-input-*")
		if err != nil {
			return nil, err
		}
		if _, err = io.Copy(os.Stdin, tempInput); err != nil {
			return nil, err
		}
		runner.tempFile = tempInput.Name()
		tempInput.Close()
	}

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
	os.Remove(r.tempFile)
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	if !strings.HasSuffix(r.options.Templates, ".yaml") {
		gologger.Fatalf("Could not run recognize template extension: %s\n", r.options.Templates)
	}

	// If the template path is a single template and not a glob, use that.
	if !strings.Contains(r.options.Templates, "*") {
		template, err := templates.ParseTemplate(r.options.Templates)
		if err != nil {
			gologger.Errorf("Could not parse template file '%s': %s\n", r.options.Templates, err)
			return
		}

		// process http requests
		for _, request := range template.RequestsHTTP {
			r.processTemplateRequest(template, request)
		}

		// process dns requests
		for _, request := range template.RequestsDNS {
			r.processTemplateRequest(template, request)
		}
		return
	}

	// Handle the glob, evaluate it and run all the template file checks
	matches, err := filepath.Glob(r.options.Templates)
	if err != nil {
		gologger.Fatalf("Could not evaluate template path '%s': %s\n", r.options.Templates, err)
	}

	for _, match := range matches {
		template, err := templates.ParseTemplate(match)
		if err != nil {
			gologger.Errorf("Could not parse template file '%s': %s\n", match, err)
			return
		}
		for _, request := range template.RequestsDNS {
			r.processTemplateRequest(template, request)
		}
		for _, request := range template.RequestsHTTP {
			r.processTemplateRequest(template, request)
		}
	}
}

// processTemplate processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplateRequest(template *templates.Template, request interface{}) {
	var file *os.File
	var err error

	// Handle a list of hosts as argument
	if r.options.Targets != "" {
		file, err = os.Open(r.options.Targets)
	} else if r.options.Stdin {
		file, err = os.Open(r.tempFile)
	}
	if err != nil {
		gologger.Fatalf("Could not open targets file '%s': %s\n", r.options.Targets, err)
	}
	r.processTemplateWithList(template, request, file)
	file.Close()
}

// processDomain processes the list with a template
func (r *Runner) processTemplateWithList(template *templates.Template, request interface{}, reader io.Reader) {
	// Display the message for the template
	message := fmt.Sprintf("[%s] Loaded template %s (@%s)", template.ID, template.Info.Name, template.Info.Author)
	if template.Info.Severity != "" {
		message += " [" + template.Info.Severity + "]"
	}
	gologger.Infof("%s\n", message)

	limiter := make(chan struct{}, r.options.Threads)
	wg := &sync.WaitGroup{}

	var writer *bufio.Writer
	if r.output != nil {
		writer = bufio.NewWriter(r.output)
		defer writer.Flush()
	}

	var httpExecutor *executor.HTTPExecutor
	var dnsExecutor *executor.DNSExecutor

	// Create an executor based on the request type.
	switch value := request.(type) {
	case *requests.DNSRequest:
		dnsExecutor = executor.NewDNSExecutor(&executor.DNSOptions{
			Template:   template,
			DNSRequest: value,
			Writer:     writer,
		})
	case *requests.HTTPRequest:
		httpExecutor = executor.NewHTTPExecutor(&executor.HTTPOptions{
			Template:    template,
			HTTPRequest: value,
			Writer:      writer,
			Timeout:     r.options.Timeout,
			Retries:     r.options.Retries,
		})
	}

	scanner := bufio.NewScanner(reader)
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
				err = httpExecutor.ExecuteHTTP(text)
			}
			if dnsExecutor != nil {
				err = dnsExecutor.ExecuteDNS(text)
			}
			if err != nil {
				gologger.Warningf("Could not execute step: %s\n", err)
			}
			<-limiter
			wg.Done()
		}(text)
	}
	close(limiter)
	wg.Wait()
}
