package executor

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/pkg/requests"
	"github.com/projectdiscovery/nuclei/pkg/templates"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// DNSExecutor is a client for performing a DNS request
// for a template.
type DNSExecutor struct {
	dnsClient  *retryabledns.Client
	template   *templates.Template
	dnsRequest *requests.DNSRequest
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// NewDNSExecutor creates a new DNS executor from a template
// and a DNS request query.
func NewDNSExecutor(template *templates.Template, dnsRequest *requests.DNSRequest) *DNSExecutor {
	dnsClient := retryabledns.New(DefaultResolvers, dnsRequest.Retries)

	executer := &DNSExecutor{
		dnsClient:  dnsClient,
		template:   template,
		dnsRequest: dnsRequest,
	}
	return executer
}

// ExecuteDNS executes the DNS request on a URL
func (e *DNSExecutor) ExecuteDNS(URL string) {
	// Parse the URL and return domain if URL.
	var domain string
	if isURL(URL) {
		domain = extractDomain(URL)
	} else {
		domain = URL
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := e.dnsRequest.MakeDNSRequest(URL)
	if err != nil {
		gologger.Warningf("[%s] Could not make request %s: %s\n", e.template.ID, domain, err)
		return
	}

	// Send the request to the target servers
	resp, err := e.dnsClient.Do(compiledRequest)
	if err != nil {
		gologger.Warningf("[%s] Could not send request %s: %s\n", e.template.ID, domain, err)
		return
	}

	for _, matcher := range e.dnsRequest.Matchers {
		// Check if the matcher matched
		if !matcher.MatchDNS(resp) {
			return
		}
	}

	// If there is an extractor, run it.
	var extractorResults []string
	for _, extractor := range e.dnsRequest.Extractors {
		extractorResults = append(extractorResults, extractor.ExtractDNS(resp.String())...)
	}
}
