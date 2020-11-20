package executer

import (
	"fmt"
	"os"
	"regexp"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/bufwriter"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/internal/tracelog"
	"github.com/projectdiscovery/nuclei/v2/pkg/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	retryabledns "github.com/projectdiscovery/retryabledns"
	"go.uber.org/ratelimit"
)

// DNSExecuter is a client for performing a DNS request
// for a template.
type DNSExecuter struct {
	// hm            *hybrid.HybridMap // Unused
	coloredOutput bool
	debug         bool
	jsonOutput    bool
	jsonRequest   bool
	noMeta        bool
	Results       bool
	traceLog      tracelog.Log
	dnsClient     *retryabledns.Client
	template      *templates.Template
	dnsRequest    *requests.DNSRequest
	writer        *bufwriter.Writer
	ratelimiter   ratelimit.Limiter

	colorizer   colorizer.NucleiColorizer
	decolorizer *regexp.Regexp
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// DNSOptions contains configuration options for the DNS executer.
type DNSOptions struct {
	ColoredOutput bool
	Debug         bool
	JSON          bool
	JSONRequests  bool
	NoMeta        bool
	TraceLog      tracelog.Log
	Template      *templates.Template
	DNSRequest    *requests.DNSRequest
	Writer        *bufwriter.Writer

	Colorizer   colorizer.NucleiColorizer
	Decolorizer *regexp.Regexp
	RateLimiter ratelimit.Limiter
}

// NewDNSExecuter creates a new DNS executer from a template
// and a DNS request query.
func NewDNSExecuter(options *DNSOptions) *DNSExecuter {
	dnsClient := retryabledns.New(DefaultResolvers, options.DNSRequest.Retries)

	executer := &DNSExecuter{
		debug:         options.Debug,
		noMeta:        options.NoMeta,
		jsonOutput:    options.JSON,
		traceLog:      options.TraceLog,
		jsonRequest:   options.JSONRequests,
		dnsClient:     dnsClient,
		template:      options.Template,
		dnsRequest:    options.DNSRequest,
		writer:        options.Writer,
		coloredOutput: options.ColoredOutput,
		colorizer:     options.Colorizer,
		decolorizer:   options.Decolorizer,
		ratelimiter:   options.RateLimiter,
	}

	return executer
}

// ExecuteDNS executes the DNS request on a URL
func (e *DNSExecuter) ExecuteDNS(p *progress.Progress, reqURL string) *Result {
	result := &Result{}

	// Parse the URL and return domain if URL.
	var domain string
	if isURL(reqURL) {
		domain = extractDomain(reqURL)
	} else {
		domain = reqURL
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := e.dnsRequest.MakeDNSRequest(domain)
	if err != nil {
		e.traceLog.Request(e.template.ID, domain, "dns", err)
		result.Error = errors.Wrap(err, "could not make dns request")
		p.Drop(1)
		return result
	}
	e.traceLog.Request(e.template.ID, domain, "dns", nil)

	if e.debug {
		gologger.Infof("Dumped DNS request for %s (%s)\n\n", reqURL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", compiledRequest.String())
	}

	// Send the request to the target servers
	resp, err := e.dnsClient.Do(compiledRequest)
	if err != nil {
		result.Error = errors.Wrap(err, "could not send dns request")
		p.Drop(1)
		return result
	}
	p.Update()

	gologger.Verbosef("Sent for [%s] to %s\n", "dns-request", e.template.ID, reqURL)

	if e.debug {
		gologger.Infof("Dumped DNS response for %s (%s)\n\n", reqURL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", resp.String())
	}

	matcherCondition := e.dnsRequest.GetMatchersCondition()

	for _, matcher := range e.dnsRequest.Matchers {
		// Check if the matcher matched
		if !matcher.MatchDNS(resp) {
			// If the condition is AND we haven't matched, return.
			if matcherCondition == matchers.ANDCondition {
				return result
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition && len(e.dnsRequest.Extractors) == 0 {
				e.writeOutputDNS(domain, compiledRequest, resp, matcher, nil)
				result.GotResults = true
			}
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	var extractorResults []string

	for _, extractor := range e.dnsRequest.Extractors {
		for match := range extractor.ExtractDNS(resp) {
			if !extractor.Internal {
				extractorResults = append(extractorResults, match)
			}
		}
	}

	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(e.dnsRequest.Extractors) > 0 || matcherCondition == matchers.ANDCondition {
		e.writeOutputDNS(domain, compiledRequest, resp, nil, extractorResults)

		result.GotResults = true
	}

	return result
}

// Close closes the dns executer for a template.
func (e *DNSExecuter) Close() {}
