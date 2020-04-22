package requests

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/valyala/fasttemplate"
)

// DNSRequest contains a request to be made from a template
type DNSRequest struct {
	Recursion bool `yaml:"recursion"`
	// Path contains the path/s for the request
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Class string `yaml:"class"`

	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
}

// MakeDNSRequest creates a *dns.Request from a request template
func (r *DNSRequest) MakeDNSRequest(domain string) (*dns.Msg, error) {

	domain = dns.Fqdn(domain)

	// Build a request on the specified URL
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = r.Recursion

	var q dns.Question

	t := fasttemplate.New(r.Name, "{{", "}}")
	q.Name = dns.Fqdn(t.ExecuteString(map[string]interface{}{
		"FQDN": domain,
	}))

	qclass, err := toQClass(r.Class)
	if err != nil {
		return nil, err
	}
	q.Qclass = qclass

	qtype, err := toQType(r.Type)
	if err != nil {
		return nil, err
	}
	q.Qtype = qtype

	req.Question = append(req.Question, q)

	return req, nil
}

func toQType(ttype string) (rtype uint16, err error) {
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
		rtype = dns.TypeNone
		err = fmt.Errorf("incorrect type")
	}

	return
}

func toQClass(tclass string) (rclass uint16, err error) {
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
		err = fmt.Errorf("incorrect class")
	}

	return
}
