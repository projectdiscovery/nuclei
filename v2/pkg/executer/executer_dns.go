package executer

import (
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

	return result
}

// Close closes the dns executer for a template.
func (e *DNSExecuter) Close() {}
