package dnsclientpool

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/retryabledns/doh"
)

// Client sends the DNS queries of a template. It sends queries for template
// DoH and DoT resolvers itself, because the retryabledns clients dial and
// follow redirects without the network policy of the scan.
type Client struct {
	*retryabledns.Client

	resolvers []resolver
	retries   int
	index     uint32
	doh       *doh.Client
	transport *http.Transport
	dial      func(ctx context.Context, network, address string) (net.Conn, error)
	timeout   time.Duration
}

// resolver is one template resolver. url is set for a DoH resolver and dot
// for a DoT resolver, and both are empty for a resolver that retryabledns
// queries over UDP or TCP.
type resolver struct {
	url    string
	method doh.Method
	dot    string
}

var (
	// policyClients holds the clients with DoH or DoT resolvers of each execution,
	// because each one dials with the dialer of its execution.
	policyClients = map[string]map[string]*Client{}
	policyMu      sync.Mutex

	// dotRootCAs verifies DoT certificates, and nil uses the system roots.
	dotRootCAs *x509.CertPool
)

func hasPolicyResolver(resolvers []string) bool {
	for _, r := range resolvers {
		if strings.HasPrefix(r, "doh:") || strings.HasPrefix(r, "dot:") {
			return true
		}
	}
	return false
}

// parseDotResolver returns the host and port of a resolver such as
// dot:dns.example or dot:dns.example:853, in the same way as retryabledns.
func parseDotResolver(r string) (resolver, bool) {
	if !strings.HasPrefix(r, "dot:") {
		return resolver{}, false
	}
	address := strings.TrimPrefix(r, "dot:")
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "853")
	}
	return resolver{dot: address}, true
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
		if parsed, ok := parseDotResolver(r); ok {
			client.resolvers = append(client.resolvers, parsed)
			continue
		}
		client.resolvers = append(client.resolvers, resolver{})
		networkResolvers = append(networkResolvers, r)
	}
	// Trace and the UDP and TCP resolvers still go through retryabledns.
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
	client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialers := protocolstate.GetDialersWithId(executionID)
		if dialers == nil || dialers.Fastdialer == nil {
			return nil, fmt.Errorf("dialers not initialized for %s", executionID)
		}
		return dialers.Fastdialer.Dial(ctx, network, address)
	}
	client.timeout = options.GetTimeouts().DialTimeout
	client.transport = &http.Transport{
		DialContext: client.dial,
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
		} else if r.dot != "" {
			resp, err = c.queryDoT(r.dot, msg)
		} else {
			resp, err = c.Client.Do(msg)
		}
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}
	return resp, retryabledns.ErrRetriesExceeded
}

// queryDoT sends a DNS message over TLS to address. It dials through the scan
// dialer and verifies the certificate against the resolver host, as the
// retryabledns DoT client does.
func (c *Client) queryDoT(address string, msg *dns.Msg) (*dns.Msg, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = retryabledns.DefaultOptions.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := c.dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: dotRootCAs, MinVersion: tls.VersionTLS12})
	defer func() { _ = tlsConn.Close() }()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	dnsClient := &dns.Client{Net: "tcp-tls", Timeout: timeout}
	resp, _, err := dnsClient.ExchangeWithConn(msg, &dns.Conn{Conn: tlsConn})
	return resp, err
}

// Close drops the clients with DoH or DoT resolvers of an execution.
func Close(executionID string) {
	policyMu.Lock()
	clients := policyClients[executionID]
	delete(policyClients, executionID)
	policyMu.Unlock()
	for _, client := range clients {
		client.transport.CloseIdleConnections()
	}
}
