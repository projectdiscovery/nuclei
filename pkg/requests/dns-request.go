package requests

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
)

// DNSRequest contains a request to be made from a template
type DNSRequest struct {
	Recursion bool `yaml:"recursion"`
	// Path contains the path/s for the request
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Class   string `yaml:"class"`
	Retries int    `yaml:"retries"`
	// Raw contains a raw request
	Raw string `yaml:"raw,omitempty"`

	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// matchersCondition is internal condition for the matchers.
	matchersCondition matchers.ConditionType
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
}

// GetMatchersCondition returns the condition for the matcher
func (r *DNSRequest) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}

// SetMatchersCondition sets the condition for the matcher
func (r *DNSRequest) SetMatchersCondition(condition matchers.ConditionType) {
	r.matchersCondition = condition
}

// MakeDNSRequest creates a *dns.Request from a request template
func (r *DNSRequest) MakeDNSRequest(domain string) (*dns.Msg, error) {
	domain = dns.Fqdn(domain)

	// Build a request on the specified URL
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = r.Recursion

	var q dns.Question

	replacer := newReplacer(map[string]interface{}{"FQDN": domain})

	q.Name = dns.Fqdn(replacer.Replace(r.Name))
	q.Qclass = toQClass(r.Class)
	q.Qtype = toQType(r.Type)

	req.Question = append(req.Question, q)

	return req, nil
}

func toQType(ttype string) (rtype uint16) {
	ttype = strings.TrimSpace(strings.ToUpper(ttype))

	switch ttype {
	case "A":
		rtype = dns.TypeA
	case "NS":
		rtype = dns.TypeNS
	case "CNAME":
		rtype = dns.TypeCNAME
	case "SOA":
		rtype = dns.TypeSOA
	case "PTR":
		rtype = dns.TypePTR
	case "MX":
		rtype = dns.TypeMX
	case "TXT":
		rtype = dns.TypeTXT
	case "AAAA":
		rtype = dns.TypeAAAA
	default:
		rtype = dns.TypeA
	}
	return
}

func toQClass(tclass string) (rclass uint16) {
	tclass = strings.TrimSpace(strings.ToUpper(tclass))

	switch tclass {
	case "INET":
		rclass = dns.ClassINET
	case "CSNET":
		rclass = dns.ClassCSNET
	case "CHAOS":
		rclass = dns.ClassCHAOS
	case "HESIOD":
		rclass = dns.ClassHESIOD
	case "NONE":
		rclass = dns.ClassNONE
	case "ANY":
		rclass = dns.ClassANY
	default:
		// Use INET by default.
		rclass = dns.ClassINET
	}
	return
}
