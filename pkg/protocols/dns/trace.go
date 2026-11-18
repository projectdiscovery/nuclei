package dns

import (
	"context"
	"math/rand"
	"net"

	"github.com/miekg/dns"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/retryabledns"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// traceNameServerPort is the port of the name servers that a trace queries.
var traceNameServerPort = "53"

// trace follows the delegation of host from the root servers in the same way
// as retryabledns.Client.Trace, but it skips name server addresses that the
// network policy denies. The name servers come from the answers, so the owner
// of a zone could otherwise send the queries of a trace to internal addresses.
func trace(executionID string, client *dnsclientpool.Client, host string, requestType uint16, maxRecursion int) (*retryabledns.TraceData, error) {
	var traceData retryabledns.TraceData
	host = dns.CanonicalName(host)
	servers := retryabledns.RootDNSServersIPv4
	seenNS := make(map[string]struct{})
	seenCName := make(map[string]int)
	for i := 1; i < maxRecursion; i++ {
		responses, err := client.QueryParallel(host, requestType, servers)
		if err != nil {
			return nil, err
		}
		for _, server := range servers {
			seenNS[server] = struct{}{}
		}
		if len(responses) == 0 {
			return &traceData, nil
		}
		for _, dnsData := range responses {
			if dnsData != nil && len(dnsData.Resolver) > 0 {
				traceData.DNSData = append(traceData.DNSData, dnsData)
			}
		}

		var nameServers []string
		var nextCname string
		for _, dnsData := range responses {
			if dnsData == nil {
				continue
			}
			for _, ns := range dnsData.NS {
				ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", ns)
				if err != nil {
					continue
				}
				for _, ip := range ips {
					if !protocolstate.IsHostAllowed(executionID, ip.String()) {
						continue
					}
					nameServers = append(nameServers, net.JoinHostPort(ip.String(), traceNameServerPort))
				}
			}
			if nextCname == "" && len(dnsData.CNAME) > 0 {
				nextCname = dnsData.CNAME[0]
			}
		}
		nameServers = sliceutil.Dedupe(nameServers)
		if len(nameServers) == 0 {
			break
		}

		server := nameServers[rand.Intn(len(nameServers))] // #nosec G404
		if _, ok := seenNS[server]; ok && nextCname == "" {
			break
		}
		servers = []string{server}

		if nextCname != "" {
			seenCName[nextCname]++
			if seenCName[nextCname] > retryabledns.DefaultMaxPerCNAMEFollows {
				break
			}
			host = nextCname
		}
	}
	return &traceData, nil
}
