package executer

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

// DNSExecuter is a client for performing a DNS request
// for a template.
type DNSExecuter struct {
	template *templates.Template
}

// DNSOptions contains configuration options for the DNS executer.
type DNSOptions struct {
	Template   *templates.Template
	DNSRequest *requests.DNSRequest
}

// NewDNSExecuter creates a new DNS executer from a template
// and a DNS request query.
func NewDNSExecuter(options *DNSOptions) *DNSExecuter {

	executer := &DNSExecuter{
		debug:         options.Debug,
		noMeta:        options.NoMeta,
		jsonOutput:    options.JSON,
		traceLog:      options.TraceLog,
		jsonRequest:   options.JSONRequests,
		dnsClient:     dnsClient,
		vhost:         options.VHost,
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
	if e.vhost {
		parts := strings.Split(reqURL, ",")
		reqURL = parts[0]
	}

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

	return result
}

// Close closes the dns executer for a template.
func (e *DNSExecuter) Close() {}
