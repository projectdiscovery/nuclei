package dns

import (
	"strings"

	"github.com/miekg/dns"
)

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
}
