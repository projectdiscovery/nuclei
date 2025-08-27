package expand

import (
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
)

// Expands CIDR to IPs
func CIDR(value string) []string {
	var ips []string
	ipsCh, _ := mapcidr.IPAddressesAsStream(value)
	for ip := range ipsCh {
		ips = append(ips, ip)
	}
	return ips
}

// Expand ASN to IPs
func ASN(value string) []string {
	var ips []string
	cidrs, _ := asn.GetCIDRsForASNNum(value)
	for _, cidr := range cidrs {
		ips = append(ips, CIDR(cidr.String())...)
	}
	return ips
}
