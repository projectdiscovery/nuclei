package protocolstate

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/reqx"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

// rawNewLine is the wire-level line terminator used for raw request serialization.
const rawNewLine = "\r\n"

// RawHeader is a single ordered raw HTTP header that preserves the exact key
// text and ordering. It replaces github.com/projectdiscovery/rawhttp/client.Header.
type RawHeader struct {
	Key   string
	Value string
}

// RawHeaders is an ordered list of raw headers, replacing rawhttp/client.Headers.
type RawHeaders []RawHeader

// RawHTTPOptions configures a single raw (unsafe) HTTP request. It mirrors the
// subset of rawhttp.Options that nuclei relies on.
type RawHTTPOptions struct {
	Timeout                time.Duration
	FollowRedirects        bool
	MaxRedirects           int
	AutomaticHostHeader    bool
	AutomaticContentLength bool
	CustomHeaders          RawHeaders
	ForceReadAllBody       bool
	CustomRawBytes         []byte
	Proxy                  string
	SNI                    string
	FastDialer             *fastdialer.Dialer
}

// DefaultRawHTTPOptions returns the default raw client options, matching the
// historical rawhttp.DefaultOptions.
func DefaultRawHTTPOptions() *RawHTTPOptions {
	return &RawHTTPOptions{
		Timeout:                30 * time.Second,
		FollowRedirects:        true,
		MaxRedirects:           10,
		AutomaticHostHeader:    true,
		AutomaticContentLength: true,
	}
}

// Clone returns a shallow copy of the options so callers can mutate per request.
func (o *RawHTTPOptions) Clone() *RawHTTPOptions {
	if o == nil {
		return DefaultRawHTTPOptions()
	}
	clone := *o
	return &clone
}

// RawHTTPClient is a reqx-backed replacement for rawhttp.Client. It sends
// wire-level (unsafe) HTTP/1.1 requests by serializing them to exact bytes and
// handing them to reqx's raw engine via SetRawRequest, which writes them
// verbatim on the wire.
type RawHTTPClient struct {
	client  *reqx.Client
	Options *RawHTTPOptions
}

// newRawReqxClient builds the underlying reqx client used by the raw paths.
// It runs in raw mode (no automatic header/path mangling), forces HTTP/1.1,
// keeps fastdialer as the dialer, and disables reqx's own redirect following so
// per-request redirect policy can be honored on a shared client.
func newRawReqxClient(timeout time.Duration, dialer *fastdialer.Dialer, sni, proxy string, pipelining bool, pipelineDepth int) *reqx.Client {
	opts := []reqx.Option{
		reqx.WithInsecureSkipVerify(),
		reqx.WithTLSMinVersion(tls.VersionTLS10),
		reqx.WithForceHTTP1(),
		reqx.WithKeepAlive(!pipelining),
		reqx.WithRawMode(),
	}
	if timeout > 0 {
		opts = append(opts, reqx.WithTimeout(timeout))
	}
	if dialer != nil {
		opts = append(opts, reqx.WithDialer(reqx.DialerFunc(dialer.Dial)))
	}
	if sni != "" {
		opts = append(opts, reqx.WithSNI(sni))
	}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			opts = append(opts, reqx.WithProxyURL(u))
		}
	}
	if pipelining {
		opts = append(opts, reqx.WithPipelining(true))
		if pipelineDepth > 0 {
			opts = append(opts, reqx.WithPipelineDepth(pipelineDepth))
		}
	}
	client := reqx.New(opts...)
	// never auto-follow: redirects are followed manually so that per-request
	// FollowRedirects / MaxRedirects are honored on a shared client.
	client.SetRedirectPolicy(func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	})
	client.SetMaxRedirects(1 << 30)
	return client
}

// NewRawHTTPClient creates a new reqx-backed raw client with the provided options.
func NewRawHTTPClient(options *RawHTTPOptions) *RawHTTPClient {
	if options == nil {
		options = DefaultRawHTTPOptions()
	}
	client := newRawReqxClient(options.Timeout, options.FastDialer, options.SNI, options.Proxy, false, 0)
	return &RawHTTPClient{client: client, Options: options}
}

// DoRaw performs a raw request using the client's default options.
func (c *RawHTTPClient) DoRaw(method, reqURL, uripath string, headers map[string][]string, body io.Reader) (*http.Response, error) {
	return c.DoRawWithOptions(method, reqURL, uripath, headers, body, c.Options)
}

// DoRawWithOptions performs a raw request with per-request options.
func (c *RawHTTPClient) DoRawWithOptions(method, reqURL, uripath string, headers map[string][]string, body io.Reader, options *RawHTTPOptions) (*http.Response, error) {
	if options == nil {
		options = c.Options
	}
	bodyBytes, bodyProvided, err := readBody(body)
	if err != nil {
		return nil, err
	}
	return c.do(method, reqURL, uripath, headers, bodyBytes, bodyProvided, options, 0)
}

func (c *RawHTTPClient) do(method, reqURL, uripath string, headers map[string][]string, body []byte, bodyProvided bool, options *RawHTTPOptions, depth int) (*http.Response, error) {
	rawBytes, err := serializeRawRequest(method, reqURL, uripath, headers, body, bodyProvided, options)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.R().SetRawRequest(rawBytes).Send(method, dialURLFromRaw(reqURL))
	if err != nil {
		return nil, err
	}
	httpResp := resp.Response
	if httpResp == nil {
		return nil, fmt.Errorf("rawhttp: nil response")
	}

	maxRedirects := options.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	if options.FollowRedirects && isRedirectStatus(httpResp.StatusCode) && depth < maxRedirects {
		if loc := httpResp.Header.Get("Location"); loc != "" {
			_, _ = io.Copy(io.Discard, httpResp.Body)
			_ = httpResp.Body.Close()
			next := resolveLocation(reqURL, loc)
			// after a redirect we rebuild the request for the new URL, so any
			// custom raw bytes / explicit uri path no longer apply.
			nextOptions := options.Clone()
			nextOptions.CustomRawBytes = nil
			return c.do(method, next, "", headers, body, bodyProvided, nextOptions, depth+1)
		}
	}
	return httpResp, nil
}

// RawPipelineOptions configures the turbo (HTTP/1.1 pipelining) client.
type RawPipelineOptions struct {
	Host               string
	MaxConnections     int
	MaxPendingRequests int
	Timeout            time.Duration
	FastDialer         *fastdialer.Dialer
	SNI                string
	Proxy              string
}

// RawPipelineClient is a reqx-backed replacement for rawhttp.PipelineClient,
// used by nuclei's turbo/pipeline mode.
type RawPipelineClient struct {
	client  *reqx.Client
	options *RawHTTPOptions
}

// NewRawPipelineClient creates a new reqx-backed pipelining client.
func NewRawPipelineClient(opts *RawPipelineOptions) *RawPipelineClient {
	if opts == nil {
		opts = &RawPipelineOptions{}
	}
	client := newRawReqxClient(opts.Timeout, opts.FastDialer, opts.SNI, opts.Proxy, true, opts.MaxPendingRequests)
	ro := DefaultRawHTTPOptions()
	ro.FollowRedirects = false
	return &RawPipelineClient{client: client, options: ro}
}

// DoRaw sends a raw pipelined request.
func (c *RawPipelineClient) DoRaw(method, reqURL, uripath string, headers map[string][]string, body io.Reader) (*http.Response, error) {
	bodyBytes, bodyProvided, err := readBody(body)
	if err != nil {
		return nil, err
	}
	rawBytes, err := serializeRawRequest(method, reqURL, uripath, headers, bodyBytes, bodyProvided, c.options)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.R().SetRawRequest(rawBytes).Send(method, dialURLFromRaw(reqURL))
	if err != nil {
		return nil, err
	}
	if resp.Response == nil {
		return nil, fmt.Errorf("rawhttp: nil response")
	}
	return resp.Response, nil
}

// Dor sends a retryablehttp request over the pipelined connection.
func (c *RawPipelineClient) Dor(req *retryablehttp.Request) (*http.Response, error) {
	var body io.Reader
	if req.Body != nil {
		body = req.Body
	}
	return c.DoRaw(req.Method, req.URL.String(), "", map[string][]string(req.Header), body)
}

// DumpRequestRaw renders the wire-level representation of a raw request,
// replacing rawhttp.DumpRequestRaw. It shares the serializer used to send raw
// requests, so the dumped bytes match what is sent.
func DumpRequestRaw(method, reqURL, uripath string, headers map[string][]string, body io.Reader, options *RawHTTPOptions) ([]byte, error) {
	if options == nil {
		options = DefaultRawHTTPOptions()
	}
	bodyBytes, bodyProvided, err := readBody(body)
	if err != nil {
		return nil, err
	}
	return serializeRawRequest(method, reqURL, uripath, headers, bodyBytes, bodyProvided, options)
}

// serializeRawRequest builds the exact wire bytes for a raw HTTP/1.1 request.
// When CustomRawBytes is set, it is returned verbatim. Otherwise the request
// line, headers (ordered CustomHeaders take precedence over the map), optional
// Host and Content-Length, and body are assembled with CRLF terminators.
func serializeRawRequest(method, reqURL, uripath string, headers map[string][]string, body []byte, bodyProvided bool, options *RawHTTPOptions) ([]byte, error) {
	if len(options.CustomRawBytes) > 0 {
		return options.CustomRawBytes, nil
	}
	if method == "" {
		method = http.MethodGet
	}

	u, err := urlutil.ParseURL(reqURL, true)
	if err != nil {
		return nil, err
	}

	path := uripath
	if path == "" {
		path = u.Path
		if path == "" {
			path = "/"
		}
		if !u.Params.IsEmpty() {
			path += "?" + u.Params.Encode()
		}
	}

	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1" + rawNewLine)

	if len(options.CustomHeaders) > 0 {
		for _, h := range options.CustomHeaders {
			if h.Value != "" {
				b.WriteString(h.Key + ": " + h.Value + rawNewLine)
			} else {
				b.WriteString(h.Key + rawNewLine)
			}
		}
	} else {
		if _, ok := headers["Host"]; !ok && options.AutomaticHostHeader {
			b.WriteString("Host: " + u.Host + rawNewLine)
		}
		for key, values := range headers {
			for _, value := range values {
				if value != "" {
					b.WriteString(key + ": " + value + rawNewLine)
				} else {
					b.WriteString(key + rawNewLine)
				}
			}
		}
	}

	if options.AutomaticContentLength && bodyProvided {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + rawNewLine)
	}

	b.WriteString(rawNewLine)
	if len(body) > 0 {
		b.Write(body)
	}

	return []byte(b.String()), nil
}

// dialURLFromRaw returns a scheme://host URL suitable for dialing. The actual
// request line/path lives in the raw bytes, so the dial URL only needs the
// scheme and host.
func dialURLFromRaw(reqURL string) string {
	u, err := urlutil.ParseURL(reqURL, true)
	if err != nil {
		return reqURL
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + u.Host
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// resolveLocation mirrors rawhttp's redirect handling: absolute URLs are used
// as-is, root-relative locations are joined to scheme://host, anything else is
// passed through verbatim.
func resolveLocation(baseURL, location string) string {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}
	u, err := urlutil.ParseURL(baseURL, true)
	if err != nil {
		return location
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if strings.HasPrefix(location, "/") {
		return fmt.Sprintf("%s://%s%s", scheme, u.Host, location)
	}
	return location
}

func readBody(body io.Reader) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}
