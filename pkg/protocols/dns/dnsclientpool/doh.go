package dnsclientpool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/retryabledns/doh"
)

// Client sends the DNS queries of a template. It sends queries for template
// DoH resolvers itself, because the retryabledns DoH client dials and follows
// redirects without the network policy of the scan.
type Client struct {
	*retryabledns.Client

	resolvers []resolver
	retries   int
	index     uint32
	doh       *doh.Client
	transport *http.Transport
}

// resolver is one template resolver. url is empty for a resolver that
// retryabledns queries over UDP, TCP or DoT.
type resolver struct {
	url    string
	method doh.Method
}

var (
	// policyClients holds the clients with DoH resolvers of each execution,
	// because each one dials with the dialer of its execution.
	policyClients = map[string]map[string]*Client{}
	policyMu      sync.Mutex
)

func hasDohResolver(resolvers []string) bool {
	for _, r := range resolvers {
		if strings.HasPrefix(r, "doh:") {
			return true
		}
	}
	return false
}

// parseDohResolver returns the URL and method of a resolver such as
// doh:https://dns.example/dns-query:get, in the same way as retryabledns.
func parseDohResolver(r string) (resolver, bool) {
	if !strings.HasPrefix(r, "doh:") {
		return resolver{}, false
	}
	u := strings.TrimPrefix(r, "doh:")
	method := doh.MethodPost
	for _, suffix := range []string{":get", ":post", ":jsonapi"} {
		if strings.HasSuffix(u, suffix) {
			u = strings.TrimSuffix(u, suffix)
			if suffix == ":get" {
				method = doh.MethodGet
			}
			break
		}
	}
	return resolver{url: u, method: method}, true
}

func getPolicyClient(options *types.Options, configuration *Configuration) (*Client, error) {
	executionID := options.ExecutionId
	hash := configuration.Hash()

	policyMu.Lock()
	defer policyMu.Unlock()
	if client, ok := policyClients[executionID][hash]; ok {
		return client, nil
	}

	client := &Client{retries: configuration.Retries}
	var networkResolvers []string
	for _, r := range configuration.Resolvers {
		if parsed, ok := parseDohResolver(r); ok {
			client.resolvers = append(client.resolvers, parsed)
			continue
		}
		client.resolvers = append(client.resolvers, resolver{})
		networkResolvers = append(networkResolvers, r)
	}
	// Trace and the non DoH resolvers still go through retryabledns.
	if len(networkResolvers) == 0 {
		networkResolvers = defaultResolvers
	}
	dnsClient, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: networkResolvers,
		MaxRetries:    1,
		Proxy:         options.AliveSocksProxy,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create dns client")
	}
	client.Client = dnsClient

	// The scan dialer checks every address it connects to, so redirects
	// and names that resolve to a denied address are refused too. It also
	// goes through the scan proxy when one is set.
	client.transport = &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialers := protocolstate.GetDialersWithId(executionID)
			if dialers == nil || dialers.Fastdialer == nil {
				return nil, fmt.Errorf("dialers not initialized for %s", executionID)
			}
			return dialers.Fastdialer.Dial(ctx, network, address)
		},
		// same as the retryabledns DoH client
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
	}
	client.doh = doh.NewWithOptions(doh.Options{
		HttpClient: &http.Client{
			Transport: client.transport,
			Timeout:   options.GetTimeouts().HttpTimeout,
		},
	})

	if policyClients[executionID] == nil {
		policyClients[executionID] = map[string]*Client{}
	}
	policyClients[executionID][hash] = client
	return client, nil
}

// Do sends a DNS message to the resolvers in turn until one answers with
// NOERROR, like retryabledns.Client.Do.
func (c *Client) Do(msg *dns.Msg) (*dns.Msg, error) {
	if len(c.resolvers) == 0 {
		return c.Client.Do(msg)
	}
	var resp *dns.Msg
	var err error
	for i := 0; i < c.retries; i++ {
		index := atomic.AddUint32(&c.index, 1)
		r := c.resolvers[index%uint32(len(c.resolvers))]
		if r.url != "" {
			resp, err = c.doh.QueryWithDOHMsg(r.method, doh.Resolver{URL: r.url}, msg)
		} else {
			resp, err = c.Client.Do(msg)
		}
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}
	return resp, retryabledns.ErrRetriesExceeded
}

// Close drops the clients with DoH resolvers of an execution.
func Close(executionID string) {
	policyMu.Lock()
	clients := policyClients[executionID]
	delete(policyClients, executionID)
	policyMu.Unlock()
	for _, client := range clients {
		client.transport.CloseIdleConnections()
	}
}
