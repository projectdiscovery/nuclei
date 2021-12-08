package dns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"

	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
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
	//   RequestType is the type of DNS request to make.
	RequestType DNSRequestTypeHolder `yaml:"type,omitempty" jsonschema:"title=type of dns request to make,description=Type is the type of DNS request to make,enum=A,enum=NS,enum=DS,enum=CNAME,enum=SOA,enum=PTR,enum=MX,enum=TXT,enum=AAAA"`
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
	// description: |
	//   Trace performs a trace operation for the target.
	Trace bool `yaml:"trace,omitempty" jsonschema:"title=trace operation,description=Trace performs a trace operation for the target."`
	// description: |
	//   TraceMaxRecursion is the number of max recursion allowed for trace operations
	// examples:
	//   - name: Use a retry of 100 to 150 generally
	//     value: 100
	TraceMaxRecursion int `yaml:"trace-max-recursion,omitempty"  jsonschema:"title=trace-max-recursion level for dns request,description=TraceMaxRecursion is the number of max recursion allowed for trace operations"`

	CompiledOperators *operators.Operators `yaml:"-"`
	dnsClient         *retryabledns.Client
	options           *protocols.ExecuterOptions

	// cache any variables that may be needed for operation.
	class    uint16
	question uint16

	// description: |
	//   Recursion determines if resolver should recurse all records to get fresh results.
	Recursion *bool `yaml:"recursion,omitempty" jsonschema:"title=recurse all servers,description=Recursion determines if resolver should recurse all records to get fresh results"`
	// Resolvers to use for the dns requests
	Resolvers []string `yaml:"resolvers,omitempty" jsonschema:"title=Resolvers,description=Define resolvers to use within the template"`
}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	if request.Retries == 0 {
		request.Retries = 3
	}
	if request.Recursion == nil {
		recursion := true
		request.Recursion = &recursion
	}
	dnsClientOptions := &dnsclientpool.Configuration{
		Retries: request.Retries,
	}
	if len(request.Resolvers) > 0 {
		dnsClientOptions.Resolvers = request.Resolvers
	}
	// Create a dns client for the class
	client, err := request.getDnsClient(options, nil)
	if err != nil {
		return errors.Wrap(err, "could not get dns client")
	}
	request.dnsClient = client

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	request.class = classToInt(request.Class)
	request.options = options
	request.question = questionTypeToInt(request.RequestType.String())
	return nil
}

func (request *Request) getDnsClient(options *protocols.ExecuterOptions, metadata map[string]interface{}) (*retryabledns.Client, error) {
	dnsClientOptions := &dnsclientpool.Configuration{
		Retries: request.Retries,
	}
	if len(request.Resolvers) > 0 {
		if len(request.Resolvers) > 0 {
			for _, resolver := range request.Resolvers {
				if expressions.ContainsUnresolvedVariables(resolver) != nil {
					var err error
					resolver, err = expressions.Evaluate(resolver, metadata)
					if err != nil {
						return nil, errors.Wrap(err, "could not resolve resolvers expressions")
					}
					dnsClientOptions.Resolvers = append(dnsClientOptions.Resolvers, resolver)
				}
			}
		}
		dnsClientOptions.Resolvers = request.Resolvers
	}
	return dnsclientpool.Get(options.Options, dnsClientOptions)
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 1
}

// Make returns the request to be sent for the protocol
func (request *Request) Make(domain string) (*dns.Msg, error) {
	if request.question != dns.TypePTR && net.ParseIP(domain) != nil {
		return nil, errors.New("cannot use IP address as DNS input")
	}
	domain = dns.Fqdn(domain)

	// Build a request on the specified URL
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = *request.Recursion

	var q dns.Question

	final := replacer.Replace(request.Name, generateDNSVariables(domain))

	q.Name = dns.Fqdn(final)
	q.Qclass = request.class
	q.Qtype = request.question
	req.Question = append(req.Question, q)

	req.SetEdns0(4096, false)

	switch request.question {
	case dns.TypeTXT:
		req.AuthenticatedData = true
	}

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

func generateDNSVariables(domain string) map[string]interface{} {
	parsed, err := publicsuffix.Parse(strings.TrimSuffix(domain, "."))
	if err != nil {
		return map[string]interface{}{"FQDN": domain}
	}

	domainName := strings.Join([]string{parsed.SLD, parsed.TLD}, ".")
	return map[string]interface{}{
		"FQDN": domain,
		"RDN":  domainName,
		"DN":   parsed.SLD,
		"TLD":  parsed.TLD,
		"SD":   parsed.TRD,
	}
}
