package executor

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/projectdiscovery/nuclei/pkg/requests"
	"github.com/projectdiscovery/nuclei/pkg/templates"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// DNSExecutor is a client for performing a DNS request
// for a template.
type DNSExecutor struct {
	debug       bool
	results     uint32
	dnsClient   *retryabledns.Client
	template    *templates.Template
	dnsRequest  *requests.DNSRequest
	writer      *bufio.Writer
	outputMutex *sync.Mutex
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// DNSOptions contains configuration options for the DNS executor.
type DNSOptions struct {
	Debug      bool
	Template   *templates.Template
	DNSRequest *requests.DNSRequest
	Writer     *bufio.Writer
}

// NewDNSExecutor creates a new DNS executor from a template
// and a DNS request query.
func NewDNSExecutor(options *DNSOptions) *DNSExecutor {
	dnsClient := retryabledns.New(DefaultResolvers, options.DNSRequest.Retries)

	executer := &DNSExecutor{
		debug:       options.Debug,
		results:     0,
		dnsClient:   dnsClient,
		template:    options.Template,
		dnsRequest:  options.DNSRequest,
		writer:      options.Writer,
		outputMutex: &sync.Mutex{},
	}
	return executer
}

// GotResults returns true if there were any results for the executor
func (e *DNSExecutor) GotResults() bool {
	if atomic.LoadUint32(&e.results) == 0 {
		return false
	}
	return true
}

// ExecuteDNS executes the DNS request on a URL
func (e *DNSExecutor) ExecuteDNS(URL string) error {
	// Parse the URL and return domain if URL.
	var domain string
	if isURL(URL) {
		domain = extractDomain(URL)
	} else {
		domain = URL
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := e.dnsRequest.MakeDNSRequest(domain)
	if err != nil {
		return errors.Wrap(err, "could not make dns request")
	}

	if e.debug {
		gologger.Infof("Dumped DNS request for %s (%s)\n\n", URL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", compiledRequest.String())
	}

	// Send the request to the target servers
	resp, err := e.dnsClient.Do(compiledRequest)
	if err != nil {
		return errors.Wrap(err, "could not send dns request")
	}

	gologger.Verbosef("Sent DNS request to %s\n", "dns-request", URL)

	if e.debug {
		gologger.Infof("Dumped DNS response for %s (%s)\n\n", URL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", resp.String())
	}

	matcherCondition := e.dnsRequest.GetMatchersCondition()
	for _, matcher := range e.dnsRequest.Matchers {
		// Check if the matcher matched
		if !matcher.MatchDNS(resp) {
			// If the condition is AND we haven't matched, return.
			if matcherCondition == matchers.ANDCondition {
				return nil
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition && len(e.dnsRequest.Extractors) == 0 {
				e.writeOutputDNS(domain, matcher, nil)
				atomic.CompareAndSwapUint32(&e.results, 0, 1)
			}
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	var extractorResults []string
	for _, extractor := range e.dnsRequest.Extractors {
		for match := range extractor.ExtractDNS(resp.String()) {
			extractorResults = append(extractorResults, match)
		}
	}

	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(e.dnsRequest.Extractors) > 0 || matcherCondition == matchers.ANDCondition {
		e.writeOutputDNS(domain, nil, extractorResults)
		atomic.CompareAndSwapUint32(&e.results, 0, 1)
	}
	return nil
}

// Close closes the dns executor for a template.
func (e *DNSExecutor) Close() {
	e.outputMutex.Lock()
	e.writer.Flush()
	e.outputMutex.Unlock()
}
