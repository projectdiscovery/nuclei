package runner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/projectdiscovery/nuclei/pkg/requests"
	"github.com/projectdiscovery/nuclei/pkg/templates"
	retryabledns "github.com/projectdiscovery/retryabledns"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	// output is the output file to write if any
	output      *os.File
	outputMutex *sync.Mutex
	// options contains configuration options for runner
	options *Options
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		outputMutex: &sync.Mutex{},
		options:     options,
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
		for _, request := range template.RequestsHTTP {
			r.processTemplateRequest(template, request)
		}
		for _, request := range template.RequestsDNS {
			r.processTemplateRequest(template, request)
		}
	}
}

// processTemplate processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplateRequest(template *templates.Template, request interface{}) {
	// Handle a list of hosts as argument
	if r.options.Targets != "" {
		file, err := os.Open(r.options.Targets)
		if err != nil {
			gologger.Fatalf("Could not open targets file '%s': %s\n", r.options.Targets, err)
		}
		r.processTemplateWithList(template, request, file)
		file.Close()
		return
	}

	// Handle stdin input
	if r.options.Stdin {
		r.processTemplateWithList(template, request, os.Stdin)
	}
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

	httpclient := r.makeHTTPClientByRequest(request)
	dnsclient := r.makeDNSClientByRequest(request)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		limiter <- struct{}{}
		wg.Add(1)

		go func(URL string) {
			r.sendRequest(template, request, URL, writer, httpclient, dnsclient)
			<-limiter
			wg.Done()
		}(text)
	}
	close(limiter)
	wg.Wait()
}

// sendRequest sends a request to the target based on a template
func (r *Runner) sendRequest(template *templates.Template, request interface{}, URL string, writer *bufio.Writer, httpclient *retryablehttp.Client, dnsclient *retryabledns.Client) {
	switch request.(type) {
	case *requests.HTTPRequest:
	

					// All the matchers matched, print the output on the screen
					output := buildOutputHTTP(template, req, extractorResults, matcher)
					gologger.Silentf("%s", output)

					if writer != nil {
						r.outputMutex.Lock()
						writer.WriteString(output)
						r.outputMutex.Unlock()
					}
				}
			}
		}
	case *requests.DNSRequest:

		// All the matchers matched, print the output on the screen
		output := buildOutputDNS(template, domain, extractorResults)
		gologger.Silentf("%s", output)

		if writer != nil {
			r.outputMutex.Lock()
			writer.WriteString(output)
			r.outputMutex.Unlock()
		}
	}
}
