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

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" jsonschema:"title=id of the dns request,description=ID is the optional ID of the DNS Request"`

	// description: |
	//   Name is the Hostname to make DNS request for.
	//
	//   Generally, it is set to {{FQDN}} which is the domain we get from input.
	// examples:
	//   - value: "\"{{FQDN}}\""
	Name string `yaml:"name,omitempty" jsonschema:"title=hostname to make dns request for,description=Name is the Hostname to make DNS request for"`
	// description: |
	//   Type is the type of DNS request to make.
	// values:
	//   - "A"
	//   - "NS"
	//   - "DS"
	//   - "CNAME"
	//   - "SOA"
	//   - "PTR"
	//   - "MX"
	//   - "TXT"
	//   - "AAAA"
	Type string `yaml:"type,omitempty" jsonschema:"title=type of dns request to make,description=Type is the type of DNS request to make,enum=A,enum=NS,enum=DS,enum=CNAME,enum=SOA,enum=PTR,enum=MX,enum=TXT,enum=AAAA"`
	// description: |
	//   Class is the class of the DNS request.
	//
	//   Usually it's enough to just leave it as INET.
	// values:
	//   - "inet"
	//   - "csnet"
	//   - "chaos"
	//   - "hesiod"
	//   - "none"
	//   - "any"
	Class string `yaml:"class,omitempty" jsonschema:"title=class of DNS request,description=Class is the class of the DNS request,enum=inet,enum=csnet,enum=chaos,enum=hesiod,enum=none,enum=any"`
	// description: |
	//   Retries is the number of retries for the DNS request
	// examples:
	//   - name: Use a retry of 3 to 5 generally
	//     value: 5
	Retries int `yaml:"retries,omitempty" jsonschema:"title=retries for dns request,description=Retries is the number of retries for the DNS request"`

	CompiledOperators *operators.Operators `yaml:"-"`
	dnsClient         *retryabledns.Client
	options           *protocols.ExecuterOptions

	// cache any variables that may be needed for operation.
	class    uint16
	question uint16

	// description: |
	//   Recursion determines if resolver should recurse all records to get fresh results.
	Recursion bool `yaml:"recursion,omitempty" jsonschema:"title=recurse all servers,description=Recursion determines if resolver should recurse all records to get fresh results"`
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

// classToInt converts a dns class name to its internal representation
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
