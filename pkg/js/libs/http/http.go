// Package http exposes an httpx-shaped HTTP client for nuclei JavaScript
// templates (require('nuclei/http')).
//
// Dial, TLS, and host-policy reuse the scan's fastdialer via protocolstate.
// The YAML httpclientpool is not used here to avoid an import cycle with the
// JS compiler; connection reuse still goes through fastdialer.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultTimeoutSeconds = 30
	defaultMaxRedirects   = 10
	defaultMaxBodyBytes   = 5 << 20 // 5 MiB
)

type (
	// Options configures a Client. All fields are optional.
	// @example
	// ```javascript
	// const http = require('nuclei/http');
	// const opts = new http.Options();
	// opts.TimeoutSeconds = 15;
	// opts.MaxRedirects = 5;
	// const client = new http.Client(opts);
	// ```
	Options struct {
		// TimeoutSeconds is the overall request timeout. 0 uses 30s.
		TimeoutSeconds int
		// MaxRedirects caps redirects when following (default 10).
		MaxRedirects int
		// MaxBodyBytes caps response body reads (default 5MiB). 0 uses default.
		MaxBodyBytes int
		// DisableRedirects turns off redirect following (on by default).
		DisableRedirects bool
		// DisableCookie disables the per-client cookie jar.
		DisableCookie bool
	}
)

type (
	// Client is an HTTP client for nuclei JS templates.
	// @example
	// ```javascript
	// const http = require('nuclei/http');
	// const client = new http.Client();
	// const resp = client.Get('https://example.com');
	// log(resp.StatusCode + ' ' + resp.Body);
	// ```
	Client struct {
		TimeoutSeconds  int
		FollowRedirects bool
		MaxRedirects    int
		MaxBodyBytes    int
		DisableCookie   bool

		nj      *utils.NucleiJS
		headers http.Header
		jar     *cookiejar.Jar
		once    sync.Once
	}
)

// NewClient constructs a Client with httpx-like defaults (follow redirects,
// cookie jar enabled).
//
// Constructor: constructor(public options?: Options)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	c := &Client{
		nj:              utils.NewNucleiJS(runtime),
		FollowRedirects: true,
		MaxRedirects:    defaultMaxRedirects,
		TimeoutSeconds:  defaultTimeoutSeconds,
		MaxBodyBytes:    defaultMaxBodyBytes,
		headers:         make(http.Header),
	}
	c.nj.ObjectSig = "Client(options?)"

	if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
		opts := utils.GetStructTypeSafe[Options](c.nj, call.Arguments, 0, Options{})
		if opts.TimeoutSeconds > 0 {
			c.TimeoutSeconds = opts.TimeoutSeconds
		}
		if opts.MaxRedirects > 0 {
			c.MaxRedirects = opts.MaxRedirects
		}
		if opts.MaxBodyBytes > 0 {
			c.MaxBodyBytes = opts.MaxBodyBytes
		}
		if opts.DisableRedirects {
			c.FollowRedirects = false
			c.MaxRedirects = 0
		}
		c.DisableCookie = opts.DisableCookie
	}

	return runtime.ToValue(c).ToObject(runtime)
}

func (c *Client) init() {
	c.once.Do(func() {
		if c.headers == nil {
			c.headers = make(http.Header)
		}
		if c.TimeoutSeconds <= 0 {
			c.TimeoutSeconds = defaultTimeoutSeconds
		}
		if c.MaxBodyBytes <= 0 {
			c.MaxBodyBytes = defaultMaxBodyBytes
		}
		if c.FollowRedirects && c.MaxRedirects <= 0 {
			c.MaxRedirects = defaultMaxRedirects
		}
		if !c.DisableCookie {
			jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
			if err == nil {
				c.jar = jar
			}
		}
	})
}

// SetHeader sets a default request header on the client.
// @example
// ```javascript
// const http = require('nuclei/http');
// const client = new http.Client();
// client.SetHeader('User-Agent', 'nuclei');
// ```
func (c *Client) SetHeader(key, value string) {
	c.init()
	c.headers.Set(key, value)
}

// Get performs an HTTP GET.
// @example
// ```javascript
// const http = require('nuclei/http');
// const client = new http.Client();
// const resp = client.Get('https://example.com');
// ```
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, "")
}

// Head performs an HTTP HEAD.
// @example
// ```javascript
// const http = require('nuclei/http');
// const client = new http.Client();
// const resp = client.Head('https://example.com');
// ```
func (c *Client) Head(ctx context.Context, rawURL string) (*Response, error) {
	return c.do(ctx, http.MethodHead, rawURL, "")
}

// Post performs an HTTP POST with the given body string.
// @example
// ```javascript
// const http = require('nuclei/http');
// const client = new http.Client();
// const resp = client.Post('https://example.com/login', 'user=a&pass=b');
// ```
func (c *Client) Post(ctx context.Context, rawURL, body string) (*Response, error) {
	return c.do(ctx, http.MethodPost, rawURL, body)
}

// Request performs an HTTP request with the given method and optional body.
// @example
// ```javascript
// const http = require('nuclei/http');
// const client = new http.Client();
// const resp = client.Request('PUT', 'https://example.com/item', '{"a":1}');
// ```
func (c *Client) Request(ctx context.Context, method, rawURL, body string) (*Response, error) {
	if method == "" {
		method = http.MethodGet
	}
	return c.do(ctx, strings.ToUpper(method), rawURL, body)
}

// Get is a package-level GET using a default client (redirects + cookies on).
// @example
// ```javascript
// const http = require('nuclei/http');
// const resp = http.Get('https://example.com');
// ```
func Get(ctx context.Context, rawURL string) (*Response, error) {
	return defaultClient().Get(ctx, rawURL)
}

// Head is a package-level HEAD using a default client.
// @example
// ```javascript
// const http = require('nuclei/http');
// const resp = http.Head('https://example.com');
// ```
func Head(ctx context.Context, rawURL string) (*Response, error) {
	return defaultClient().Head(ctx, rawURL)
}

// Post is a package-level POST using a default client.
// @example
// ```javascript
// const http = require('nuclei/http');
// const resp = http.Post('https://example.com/login', 'user=a&pass=b');
// ```
func Post(ctx context.Context, rawURL, body string) (*Response, error) {
	return defaultClient().Post(ctx, rawURL, body)
}

// Request is a package-level request using a default client.
// @example
// ```javascript
// const http = require('nuclei/http');
// const resp = http.Request('OPTIONS', 'https://example.com', '');
// ```
func Request(ctx context.Context, method, rawURL, body string) (*Response, error) {
	return defaultClient().Request(ctx, method, rawURL, body)
}

func defaultClient() *Client {
	return &Client{
		FollowRedirects: true,
		MaxRedirects:    defaultMaxRedirects,
		TimeoutSeconds:  defaultTimeoutSeconds,
		MaxBodyBytes:    defaultMaxBodyBytes,
		headers:         make(http.Header),
	}
}

func (c *Client) do(ctx context.Context, method, rawURL, body string) (*Response, error) {
	c.init()

	executionID := executionIDFrom(ctx, c)
	if executionID == "" {
		return nil, fmt.Errorf("http: executionId not set")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("http: invalid url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("http: url must include scheme and host")
	}

	host := parsed.Hostname()
	if !protocolstate.IsHostAllowed(executionID, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	dialers := protocolstate.GetDialersWithId(executionID)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", executionID)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		Renegotiation:      tls.RenegotiateOnceAsClient,
	}
	if host != "" {
		tlsConfig.ServerName = host
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialers.Fastdialer.Dial(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialers.Fastdialer.DialTLSWithConfig(ctx, network, addr, tlsConfig)
		},
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: time.Duration(c.TimeoutSeconds) * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(c.TimeoutSeconds) * time.Second,
	}
	if c.jar != nil {
		httpClient.Jar = c.jar
	}
	if !c.FollowRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		max := c.MaxRedirects
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return fmt.Errorf("http: stopped after %d redirects", max)
			}
			if nextHost := req.URL.Hostname(); nextHost != "" && !protocolstate.IsHostAllowed(executionID, nextHost) {
				return protocolstate.ErrHostDenied.Msgf(nextHost)
			}
			return nil
		}
	}

	var bodyReader io.Reader
	if body != "" && method != http.MethodHead && method != http.MethodGet {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	for k, vals := range c.headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Nuclei")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	limited := io.LimitReader(resp.Body, int64(c.MaxBodyBytes)+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(raw) > c.MaxBodyBytes {
		return nil, fmt.Errorf("http: response body exceeds %d bytes", c.MaxBodyBytes)
	}

	out := &Response{
		StatusCode: resp.StatusCode,
		URL:        resp.Request.URL.String(),
		Body:       string(raw),
		Headers:    flattenHeaders(resp.Header),
		header:     resp.Header.Clone(),
	}
	return out, nil
}

func executionIDFrom(ctx context.Context, c *Client) string {
	if c != nil && c.nj != nil {
		if id := c.nj.ExecutionId(); id != "" {
			return id
		}
	}
	if ctx == nil {
		return ""
	}
	if v := ctx.Value("executionId"); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}
