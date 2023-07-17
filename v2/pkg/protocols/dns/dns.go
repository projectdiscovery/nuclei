package dns

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/retryabledns"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Request contains a DNS protocol request to be made from a template
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the dns request,description=ID is the optional ID of the DNS Request"`

	// description: |
	//   Name is the Hostname to make DNS request for.
	//
	//   Generally, it is set to {{FQDN}} which is the domain we get from input.
	// examples:
	//   - value: "\"{{FQDN}}\""
	Name string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"title=hostname to make dns request for,description=Name is the Hostname to make DNS request for"`
	// description: |
	//   RequestType is the type of DNS request to make.
	RequestType DNSRequestTypeHolder `yaml:"type,omitempty" json:"type,omitempty" jsonschema:"title=type of dns request to make,description=Type is the type of DNS request to make,enum=A,enum=NS,enum=DS,enum=CNAME,enum=SOA,enum=PTR,enum=MX,enum=TXT,enum=AAAA"`
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
	Class string `yaml:"class,omitempty" json:"class,omitempty" jsonschema:"title=class of DNS request,description=Class is the class of the DNS request,enum=inet,enum=csnet,enum=chaos,enum=hesiod,enum=none,enum=any"`
	// description: |
	//   Retries is the number of retries for the DNS request
	// examples:
	//   - name: Use a retry of 3 to 5 generally
	//     value: 5
	Retries int `yaml:"retries,omitempty" json:"retries,omitempty" jsonschema:"title=retries for dns request,description=Retries is the number of retries for the DNS request"`
	// description: |
	//   Trace performs a trace operation for the target.
	Trace bool `yaml:"trace,omitempty" json:"trace,omitempty" jsonschema:"title=trace operation,description=Trace performs a trace operation for the target."`
	// description: |
	//   TraceMaxRecursion is the number of max recursion allowed for trace operations
	// examples:
	//   - name: Use a retry of 100 to 150 generally
	//     value: 100
	TraceMaxRecursion int `yaml:"trace-max-recursion,omitempty"  jsonschema:"title=trace-max-recursion level for dns request,description=TraceMaxRecursion is the number of max recursion allowed for trace operations"`

	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	AttackType generators.AttackTypeHolder `yaml:"attack,omitempty" json:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=batteringram,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads  map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty" jsonschema:"title=payloads for the network request,description=Payloads contains any payloads for the current request"`
	generator *generators.PayloadGenerator

	CompiledOperators *operators.Operators `yaml:"-"`
	dnsClient         *retryabledns.Client
	options           *protocols.ExecutorOptions

	// cache any variables that may be needed for operation.
	class    uint16
	question uint16

	// description: |
	//   Recursion determines if resolver should recurse all records to get fresh results.
	Recursion *bool `yaml:"recursion,omitempty" json:"recursion,omitempty" jsonschema:"title=recurse all servers,description=Recursion determines if resolver should recurse all records to get fresh results"`
	// Resolvers to use for the dns requests
	Resolvers []string `yaml:"resolvers,omitempty" json:"resolvers,omitempty" jsonschema:"title=Resolvers,description=Define resolvers to use within the template"`
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":   "ID of the template executed",
	"template-info": "Info Block of the template executed",
	"template-path": "Path of the template executed",
	"host":          "Host is the input to the template",
	"matched":       "Matched is the input which was matched upon",
	"request":       "Request contains the DNS request in text format",
	"type":          "Type is the type of request made",
	"rcode":         "Rcode field returned for the DNS request",
	"question":      "Question contains the DNS question field",
	"extra":         "Extra contains the DNS response extra field",
	"answer":        "Answer contains the DNS response answer field",
	"ns":            "NS contains the DNS response NS field",
	"raw,body,all":  "Raw contains the raw DNS response (default)",
	"trace":         "Trace contains trace data for DNS request if enabled",
}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Options returns executer options for http request
func (r *Request) Options() *protocols.ExecutorOptions {
	return r.options
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
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
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	request.class = classToInt(request.Class)
	request.options = options
	request.question = questionTypeToInt(request.RequestType.String())
	for name, payload := range options.Options.Vars.AsMap() {
		payloadStr, ok := payload.(string)
		// check if inputs contains the payload
		if ok && fileutil.FileExists(payloadStr) {
			if request.Payloads == nil {
				request.Payloads = make(map[string]interface{})
			}
			request.Payloads[name] = payloadStr
		}
	}

	if len(request.Payloads) > 0 {
		request.generator, err = generators.New(request.Payloads, request.AttackType.Value, request.options.TemplatePath, request.options.Options.AllowLocalFileAccess, request.options.Catalog, request.options.Options.AttackType)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}
	return nil
}

func (request *Request) getDnsClient(options *protocols.ExecutorOptions, metadata map[string]interface{}) (*retryabledns.Client, error) {
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
	if request.generator != nil {
		payloadRequests := request.generator.NewIterator().Total()
		return payloadRequests
	}

	return 1
}

// Make returns the request to be sent for the protocol
func (request *Request) Make(host string, vars map[string]interface{}) (*dns.Msg, error) {
	// Build a request on the specified URL
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = *request.Recursion

	var q dns.Question
	final := replacer.Replace(request.Name, vars)

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
	case "CAA":
		question = dns.TypeCAA
	case "TLSA":
		question = dns.TypeTLSA
	case "ANY":
		question = dns.TypeANY
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
