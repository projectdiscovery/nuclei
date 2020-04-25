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

	limiter := make(chan struct{}, r.options.Threads)
	wg := &sync.WaitGroup{}
	var channels []chan string

	// If the template path is a single template and not a glob, use that.
	if !strings.Contains(r.options.Templates, "*") {
		template, err := templates.ParseTemplate(r.options.Templates)
		if err != nil {
			gologger.Errorf("Could not parse template file '%s': %s\n", r.options.Templates, err)
			return
		}
		// process http requests
		for _, request := range template.RequestsHTTP {
			// we need a chan per request
			targets := make(chan string, 100)
			channels = append(channels, targets)
			wg.Add(1)
			go r.processTemplateWithList(limiter, wg, template, request, targets)
		}

		// process dns requests
		for _, request := range template.RequestsDNS {
			targets := make(chan string, 100)
			channels = append(channels, targets)
			wg.Add(1)
			go r.processTemplateWithList(limiter, wg, template, request, targets)
		}
	} else {
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
				targets := make(chan string, 100)
				channels = append(channels, targets)
				wg.Add(1)
				go r.processTemplateWithList(limiter, wg, template, request, targets)
			}
			for _, request := range template.RequestsDNS {
				targets := make(chan string, 100)
				channels = append(channels, targets)
				wg.Add(1)
				go r.processTemplateWithList(limiter, wg, template, request, targets)
			}
		}
	}

	go func() {
		// stream the same input among templates
		for target := range r.streamInput() {
			for _, channel := range channels {
				channel <- target
			}
		}

		for _, channel := range channels {
			close(channel)
		}
	}()

	wg.Wait()

	close(limiter)
}

func (r *Runner) streamInput() (targets chan string) {
	targets = make(chan string)

	go func() {
		defer close(targets)

		var file *os.File

		if r.options.Targets != "" {
			file, err := os.Open(r.options.Targets)
			if err != nil {
				gologger.Fatalf("Could not open targets file '%s': %s\n", r.options.Targets, err)
			}
			defer file.Close()
			return
		}

		if r.options.Stdin {
			file = os.Stdin
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			targets <- scanner.Text()
		}
	}()

	return
}

// processDomain processes the list with a template
func (r *Runner) processTemplateWithList(limiter chan struct{}, wgt *sync.WaitGroup, template *templates.Template, request interface{}, targets chan string) {
	defer wgt.Done()
	// Display the message for the template
	message := fmt.Sprintf("[%s] Loaded template %s (@%s)", template.ID, template.Info.Name, template.Info.Author)
	if template.Info.Severity != "" {
		message += " [" + template.Info.Severity + "]"
	}
	gologger.Infof("%s\n", message)

	wg := &sync.WaitGroup{}

	var writer *bufio.Writer
	if r.output != nil {
		writer = bufio.NewWriter(r.output)
		defer writer.Flush()
	}

	httpclient := r.makeHTTPClientByRequest(request)
	dnsclient := r.makeDNSClientByRequest(request)

	for target := range targets {
		if target == "" {
			continue
		}
		limiter <- struct{}{}
		wg.Add(1)

		go func(URL string) {
			r.sendRequest(template, request, URL, writer, httpclient, dnsclient)
			<-limiter
			wg.Done()
		}(target)
	}

	wg.Wait()
}

// sendRequest sends a request to the target based on a template
func (r *Runner) sendRequest(template *templates.Template, request interface{}, URL string, writer *bufio.Writer, httpclient *retryablehttp.Client, dnsclient *retryabledns.Client) {
	switch request.(type) {
	case *requests.HTTPRequest:
		if !isURL(URL) {
			break
		}
		httpRequest := request.(*requests.HTTPRequest)

		// Compile each request for the template based on the URL
		compiledRequest, err := httpRequest.MakeHTTPRequest(URL)
		if err != nil {
			gologger.Warningf("[%s] Could not make request %s: %s\n", template.ID, URL, err)
			return
		}

		// Send the request to the target servers
		for _, req := range compiledRequest {
			resp, err := httpclient.Do(req)
			if err != nil {
				if resp != nil {
					resp.Body.Close()
				}
				gologger.Warningf("[%s] Could not send request %s: %s\n", template.ID, URL, err)
				return
			}

			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				io.Copy(ioutil.Discard, resp.Body)
				resp.Body.Close()
				gologger.Warningf("[%s] Could not read body %s: %s\n", template.ID, URL, err)
				continue
			}
			resp.Body.Close()

			body := unsafeToString(data)

			var headers string
			for _, matcher := range httpRequest.Matchers {
				// Only build the headers string if the matcher asks for it
				part := matcher.GetPart()
				if part == matchers.AllPart || part == matchers.HeaderPart && headers == "" {
					headers = headersToString(resp.Header)
				}

				// Check if the matcher matched
				if matcher.Match(resp, body, headers) {
					// If there is an extractor, run it.
					var extractorResults []string
					for _, extractor := range httpRequest.Extractors {
						part := extractor.GetPart()
						if part == extractors.AllPart || part == extractors.HeaderPart && headers == "" {
							headers = headersToString(resp.Header)
						}
						extractorResults = append(extractorResults, extractor.Extract(body, headers)...)
					}

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
		// eventually extracts dns from url
		var domain string = URL
		if isURL(URL) {
			domain = extractDomain(URL)
		}

		dnsRequest := request.(*requests.DNSRequest)

		// Compile each request for the template based on the URL
		compiledRequest, err := dnsRequest.MakeDNSRequest(domain)
		if err != nil {
			gologger.Warningf("[%s] Could not make request %s: %s\n", template.ID, domain, err)
			return
		}

		// Send the request to the target servers
		resp, err := dnsclient.Do(compiledRequest)
		if err != nil {
			gologger.Warningf("[%s] Could not send request %s: %s\n", template.ID, domain, err)
			return
		}

		for _, matcher := range dnsRequest.Matchers {
			// Check if the matcher matched
			if !matcher.MatchDNS(resp) {
				return
			}
		}

		// If there is an extractor, run it.
		var extractorResults []string
		for _, extractor := range dnsRequest.Extractors {
			extractorResults = append(extractorResults, extractor.ExtractDNS(resp.String())...)
		}

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

// buildOutputHTTP builds an output text for writing results
func buildOutputHTTP(template *templates.Template, req *retryablehttp.Request, extractorResults []string, matcher *matchers.Matcher) string {
	builder := &strings.Builder{}
	builder.WriteRune('[')
	builder.WriteString(template.ID)
	if len(matcher.Name) > 0 {
		builder.WriteString(":")
		builder.WriteString(matcher.Name)
	}
	builder.WriteString("] ")

	// Escape the URL by replacing all % with %%
	URL := req.URL.String()
	escapedURL := strings.Replace(URL, "%", "%%", -1)
	builder.WriteString(escapedURL)

	// If any extractors, write the results
	if len(extractorResults) > 0 {
		builder.WriteString(" [")
		for i, result := range extractorResults {
			builder.WriteString(result)
			if i != len(extractorResults)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteString("]")
	}
	builder.WriteRune('\n')

	return builder.String()
}

// buildOutput builds an output text for writing results
func buildOutputDNS(template *templates.Template, domain string, extractorResults []string) string {
	builder := &strings.Builder{}
	builder.WriteRune('[')
	builder.WriteString(template.ID)
	builder.WriteString("] [dns] ")

	builder.WriteString(domain)

	// If any extractors, write the results
	if len(extractorResults) > 0 {
		builder.WriteString(" [")
		for i, result := range extractorResults {
			builder.WriteString(result)
			if i != len(extractorResults)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteString("]")
	}
	builder.WriteRune('\n')

	return builder.String()
}

// makeHTTPClient creates a HTTP client with configurable redirect field
func (r *Runner) makeHTTPClientByRequest(request interface{}) *retryablehttp.Client {

	redirects := false
	maxRedirects := 0
	// Request is HTTP
	if httpRequest, ok := request.(requests.HTTPRequest); ok {
		redirects = httpRequest.Redirects
		maxRedirects = httpRequest.MaxRedirects
	}

	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.RetryWaitMax = 10 * time.Second
	retryablehttpOptions.RetryMax = r.options.Retries

	// Create the HTTP Client
	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
		},
		Timeout: time.Duration(r.options.Timeout) * time.Second,
		CheckRedirect: func(_ *http.Request, requests []*http.Request) error {
			if !redirects {
				return http.ErrUseLastResponse
			}
			if maxRedirects == 0 {
				if len(requests) > 10 {
					return http.ErrUseLastResponse
				}
				return nil
			}
			if len(requests) > maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, retryablehttpOptions)
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()
	return client
}

// makeHTTPClient creates a HTTP client with configurable redirect field
func (r *Runner) makeDNSClientByRequest(request interface{}) *retryabledns.Client {
	retries := r.options.Retries
	if dnsRequest, ok := request.(*requests.DNSRequest); ok {
		retries = dnsRequest.Retries
	}

	dnsClient, _ := retryabledns.New(DefaultResolvers, retries)
	return dnsClient
}
