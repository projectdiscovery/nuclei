package dns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/retryabledns"
)

// Request contains a DNS protocol request to be made from a template
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`

	ID string `yaml:"id"`

	// Path contains the path/s for the request
	Name string `yaml:"name"`
	// Type is the type of DNS request to make
	Type string `yaml:"type"`
	// Class is the class of the DNS request
	Class string `yaml:"class"`
	// Retries is the number of retries for the DNS request
	Retries int `yaml:"retries"`

	CompiledOperators *operators.Operators
	dnsClient         *retryabledns.Client
	options           *protocols.ExecuterOptions

	// cache any variables that may be needed for operation.
	class    uint16
	question uint16

	// Recursion specifies whether to recurse all the answers.
	Recursion bool `yaml:"recursion"`
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	// Create a dns client for the class
	client, err := dnsclientpool.Get(options.Options, &dnsclientpool.Configuration{
		Retries: r.Retries,
	})
	if err != nil {
		return errors.Wrap(err, "could not get dns client")
	}
	r.dnsClient = client

	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	r.class = classToInt(r.Class)
	r.options = options
	r.question = questionTypeToInt(r.Type)
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return 1
}

// Make returns the request to be sent for the protocol
func (r *Request) Make(domain string) (*dns.Msg, error) {
	if r.question != dns.TypePTR && net.ParseIP(domain) != nil {
		return nil, errors.New("cannot use IP address as DNS input")
	}
	domain = dns.Fqdn(domain)

	// Build a request on the specified URL
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = r.Recursion

	var q dns.Question

	final := replacer.Replace(r.Name, map[string]interface{}{"FQDN": domain})

	q.Name = dns.Fqdn(final)
	q.Qclass = r.class
	q.Qtype = r.question
	req.Question = append(req.Question, q)
	return req, nil
}

// questionTypeToInt converts DNS question type to internal representation
func questionTypeToInt(questionType string) uint16 {
	questionType = strings.TrimSpace(strings.ToUpper(questionType))
	question := dns.TypeA

	switch questionType {
	case "A":
		question = dns.TypeA
	case "NS":
		question = dns.TypeNS
	case "CNAME":
		question = dns.TypeCNAME
	case "SOA":
		question = dns.TypeSOA
	case "PTR":
		question = dns.TypePTR
	case "MX":
		question = dns.TypeMX
	case "TXT":
		question = dns.TypeTXT
	case "DS":
		question = dns.TypeDS
	case "AAAA":
		question = dns.TypeAAAA
	}
	return question
}

// classToInt converts a dns class name to it's internal representation
func classToInt(class string) uint16 {
	class = strings.TrimSpace(strings.ToUpper(class))
	result := dns.ClassINET

	switch class {
	case "INET":
		result = dns.ClassINET
	case "CSNET":
		result = dns.ClassCSNET
	case "CHAOS":
		result = dns.ClassCHAOS
	case "HESIOD":
		result = dns.ClassHESIOD
	case "NONE":
		result = dns.ClassNONE
	case "ANY":
		result = dns.ClassANY
	}
	return uint16(result)
}
