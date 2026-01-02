package dns

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryabledns"
)

var IPNotFoundError = errors.New("no A or AAAA record found")

// Perform a DNS resolution for the given host using the provided resolver
// Other protocols have more performant ways of resolving hosts, this should be used within this package only
func tryToResolveHost(domain string, resolver *retryabledns.Client) (string, error) {
	// resolve is recursive so CNAMEs are resolved automatically
	ips, err := resolver.Resolve(domain)
	if err != nil {
		return "", err
	}
	// It returns first A or AAAA record found in DNS chain
	// This means that domains with multiple A records will return the first one only, also ipv4 is preferred over ipv6
	if len(ips.A) > 0 {
		return ips.A[0], nil
	}
	if len(ips.AAAA) > 0 {
		return ips.AAAA[0], nil
	}
	return "", IPNotFoundError
}
