package dns

import (
	"strings"

	"github.com/miekg/dns"
)

// Request contains a DNS protocol request to be made from a template
type Request struct {
	// Recursion specifies whether to recurse all the answers.
	Recursion bool `yaml:"recursion"`
	// Path contains the path/s for the request
	Name string `yaml:"name"`
	// Type is the type of DNS request to make
	Type string `yaml:"type"`
	// Class is the class of the DNS request
	Class string `yaml:"class"`
	// Retries is the number of retries for the DNS request
	Retries int `yaml:"retries"`
	// Raw contains a raw request
	Raw string `yaml:"raw,omitempty"`

	// cache any variables that may be needed for operation.
	class        uint16
	questionType uint16
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile() error {
	r.class = classToInt(r.Class)
	r.questionType = questionTypeToInt(r.Type)
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int64 {
	return 1
}

// Make returns the request to be sent for the protocol
func (r *Request) Make(domain string) (*dns.Msg, error) {
	domain = dns.Fqdn(domain)

	// Build a request on the specified URL
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = r.Recursion

	var q dns.Question

	replacer := newReplacer(map[string]interface{}{"FQDN": domain})

	q.Name = dns.Fqdn(replacer.Replace(r.Name))
	q.Qclass = classToInt(r.Class)
	q.Qtype = questionTypeToInt(r.Type)
	req.Question = append(req.Question, q)
	return req, nil
}

// questionTypeToInt converts DNS question type to internal representation
func questionTypeToInt(Type string) uint16 {
	Type = strings.TrimSpace(strings.ToUpper(Type))
	question := dns.TypeA

	switch Type {
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
	case "AAAA":
		question = dns.TypeAAAA
	}
	return uint16(question)
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
