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
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/projectdiscovery/nuclei/pkg/templates"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	client  *retryablehttp.Client
	options *Options
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

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
		Timeout: time.Duration(options.Timeout) * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, retryablehttp.DefaultOptionsSpraying)
	client.Backoff = retryablehttp.FullJitterBackoff()
	client.CheckRetry = retryablehttp.HostSprayRetryPolicy()

	runner.client = client
	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {}

// RunEnumeration sets up the input layer for giving input to massdns
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	// If the template path is a single template and not a glob, use that.
	if !strings.Contains(r.options.Templates, "*") {
		r.processTemplate(r.options.Templates)
	}

	// Handle the glob, evaluate it and run all the template file checks
	matches, err := filepath.Glob(r.options.Templates)
	if err != nil {
		gologger.Fatalf("Could not evaluate template path '%s': %s\n", r.options.Templates, err)
	}
	for _, match := range matches {
		r.processTemplate(match)
	}
}

// processTemplate processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplate(templatePath string) {
	template, err := templates.ParseTemplate(templatePath)
	if err != nil {
		gologger.Fatalf("Could not parse template file '%s': %s\n", templatePath, err)
	}

	// Handle a list of hosts as argument
	if r.options.Targets != "" {
		file, err := os.Open(r.options.Targets)
		if err != nil {
			gologger.Fatalf("Could not open targets file '%s': %s\n", r.options.Targets, err)
		}
		r.processTemplateWithList(template, file)
		file.Close()
		return
	}

	// Handle stdin input
	if r.options.Stdin {
		r.processTemplateWithList(template, os.Stdin)
	}
}

// processDomain processes the list with a template
func (r *Runner) processTemplateWithList(template *templates.Template, reader io.Reader) {
	// Display the message for the template
	message := fmt.Sprintf("[%s] Loaded template %s (@%s)", template.ID, template.Info.Name, template.Info.Author)
	if template.Info.Severity != "" {
		message += " [" + template.Info.Severity + "]"
	}
	gologger.Infof("%s\n", message)

	limiter := make(chan struct{}, r.options.Threads)
	wg := &sync.WaitGroup{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		limiter <- struct{}{}
		wg.Add(1)

		go func(URL string) {
			r.sendRequest(template, URL)
			<-limiter
			wg.Done()
		}(text)
	}
	close(limiter)
	wg.Wait()
}

// sendRequest sends a request to the target based on a template
func (r *Runner) sendRequest(template *templates.Template, URL string) {
	for _, request := range template.Requests {
		// Compile each request for the template based on the URL
		compiledRequest, err := request.MakeRequest(URL)
		if err != nil {
			gologger.Warningf("[%s] Could not make request %s: %s\n", template.ID, URL, err)
			continue
		}

		// Send the request to the target servers
		for _, req := range compiledRequest {
			resp, err := r.client.Do(req)
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
			for _, matcher := range request.Matchers {
				// Only build the headers string if the matcher asks for it
				switch matcher.GetPart() {
				case matchers.AllPart, matchers.HeaderPart:
					if headers == "" {
						headers = headersToString(resp.Header)
					}
				}

				// Check if the matcher matched
				if !matcher.Match(resp, body, headers) {
					continue
				}
			}

			// All the matchers matched, print the output on the screen
			gologger.Silentf("[%s] %s\n", template.ID, req.URL.String())
		}
	}
}
