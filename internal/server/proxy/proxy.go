// Package proxy implements an intercepting HTTP proxy that feeds live traffic
// into the nuclei DAST scanner. Requests are forwarded untouched; a copy of
// each intercepted request is handed to the scanner out of band.
package proxy

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

const (
	// Requests with a larger body are not mirrored at all: see captureRequest.
	maxCapturedBodySize = 4 << 20

	readHeaderTimeout = 30 * time.Second
)

// hopByHopHeaders are stripped from mirrored requests: they belong to the
// client-to-proxy leg and must not be replayed at a target.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authorization",
	"Proxy-Authenticate",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Options configures the intercepting proxy.
type Options struct {
	// Address is the host:port to listen on.
	Address string
	// CADir is the directory holding the interception CA.
	CADir string
	// Username and Password gate the proxy with basic authentication. They are
	// mandatory when Address is not a loopback address.
	Username string
	Password string
	// Verbose enables goproxy's own request logging.
	Verbose bool
	// Intercept reports whether the TLS connection to host should be decrypted.
	// Hosts it rejects are tunnelled through without inspection. Optional;
	// every host is intercepted when nil.
	Intercept func(host string) bool
	// Submit hands a captured request to the scanner. It must not block, and
	// returns false when the request could not be queued.
	Submit func(rawHTTP, targetURL string) bool
	// ForwardProxy is an optional HTTP(S) proxy URL for the forwarding leg.
	// Ambient HTTP_PROXY / HTTPS_PROXY are ignored so a leftover environment
	// variable cannot silently chain this listener.
	ForwardProxy string
}

// Proxy is an intercepting proxy that mirrors traffic into the scanner.
type Proxy struct {
	options *Options
	ca      *CA
	server  *http.Server

	intercepted          atomic.Int64
	tunnelsPassedThrough atomic.Int64
	dropped              atomic.Int64
}

// requestState is what a proxied request carries between the goproxy hooks.
// A CONNECT tunnel reuses one instance for every request inside it.
type requestState struct {
	tunnelAuthorized bool
	rawHTTP          string
}

// Stats reports what the proxy has done with the traffic it has seen.
type Stats struct {
	Intercepted int64
	// TunnelsPassedThrough counts CONNECT tunnels left encrypted, not requests:
	// their contents are never seen.
	TunnelsPassedThrough int64
	Dropped              int64
}

// New returns a proxy ready to be started.
func New(options *Options) (*Proxy, error) {
	if options.Submit == nil {
		return nil, errors.New("proxy requires a submit callback")
	}
	if err := validateBinding(options); err != nil {
		return nil, err
	}
	if _, err := parseForwardProxy(options.ForwardProxy); err != nil {
		return nil, err
	}
	ca, err := LoadOrCreateCA(options.CADir)
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{options: options, ca: ca}
	proxy.server = &http.Server{
		Handler: proxy.handler(),
		// Read and write timeouts would break long lived CONNECT tunnels, so
		// only the header read is bounded.
		ReadHeaderTimeout: readHeaderTimeout,
	}
	return proxy, nil
}

// CertPath is the on-disk path of the CA certificate users need to trust.
func (p *Proxy) CertPath() string { return p.ca.CertPath }

// CertPEM is the PEM encoded CA certificate. It never contains the key.
func (p *Proxy) CertPEM() []byte { return p.ca.CertPEM }

// Stats returns the current proxy counters.
func (p *Proxy) Stats() Stats {
	return Stats{
		Intercepted:          p.intercepted.Load(),
		TunnelsPassedThrough: p.tunnelsPassedThrough.Load(),
		Dropped:              p.dropped.Load(),
	}
}

// Start listens and serves until Close is called.
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.options.Address)
	if err != nil {
		return errors.Wrap(err, "could not listen on dast proxy address")
	}
	if err := p.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Close shuts the proxy listener down.
func (p *Proxy) Close() error {
	if p.server == nil {
		return nil
	}
	if err := p.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *Proxy) handler() http.Handler {
	handler := goproxy.NewProxyHttpServer()
	handler.Verbose = p.options.Verbose
	handler.Logger = proxyLogger{}
	handler.CertStore = newCertCache()
	// Stated rather than inherited from goproxy's default, because it is a
	// deliberate choice: the forwarding leg does not verify target certificates,
	// matching the rest of nuclei (see httpclientpool), since DAST targets
	// routinely serve self-signed ones. Interception inherently replaces the
	// browser's own validation, so this is reported at startup.
	forward, _ := parseForwardProxy(p.options.ForwardProxy)
	handler.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
		Proxy:           forward,
	}

	// Every action carries our own CA. goproxy's package level OkConnect and
	// MitmConnect close over its built-in CA, whose private key ships with the
	// library, so none of them are reused here.
	signWithOurCA := goproxy.TLSConfigFromCA(p.ca.Certificate)
	mitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: signWithOurCA}
	tunnel := &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: signWithOurCA}
	// Answering CONNECT with a challenge rather than dropping the connection is
	// what lets a browser prompt for the proxy credentials.
	challenge := &goproxy.ConnectAction{
		Action: goproxy.ConnectHijack,
		Hijack: func(req *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
			defer func() { _ = client.Close() }()
			if err := authRequiredResponse(req).Write(client); err != nil {
				gologger.Debug().Msgf("Could not write proxy auth challenge: %s", err)
			}
		},
		TLSConfig: signWithOurCA,
	}

	handler.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if !p.authorized(ctx.Req) {
			return challenge, host
		}
		// A client only sends Proxy-Authorization on CONNECT, so the successful
		// check is recorded on the context that every request inside the tunnel
		// goes on to share, rather than being repeated per request.
		ctx.UserData = &requestState{tunnelAuthorized: true}

		if p.options.Intercept != nil && !p.options.Intercept(host) {
			p.tunnelsPassedThrough.Add(1)
			return tunnel, host
		}
		return mitm, host
	})

	handler.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		state, _ := ctx.UserData.(*requestState)
		if state == nil || !state.tunnelAuthorized {
			if !p.authorized(req) {
				return req, authRequiredResponse(req)
			}
			state = &requestState{}
			ctx.UserData = state
		}
		// The body has to be captured before the transport consumes it, but the
		// response is only available later, so the raw request rides along on
		// the context until then.
		if raw, ok := captureRequest(req); ok {
			state.rawHTTP = raw
		}
		return req, nil
	})

	handler.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		p.submit(ctx)
		return resp
	})

	return handler
}

// submit mirrors an intercepted request into the scanner. It runs while the
// client is still waiting for its response, so it must stay non-blocking.
func (p *Proxy) submit(ctx *goproxy.ProxyCtx) {
	if ctx == nil || ctx.Req == nil {
		return
	}
	state, ok := ctx.UserData.(*requestState)
	if !ok || state.rawHTTP == "" {
		return
	}
	raw := state.rawHTTP
	// Cleared so a tunnel that reuses this state cannot mirror it twice.
	state.rawHTTP = ""

	p.intercepted.Add(1)
	if !p.options.Submit(raw, ctx.Req.URL.String()) {
		p.dropped.Add(1)
	}
}

func (p *Proxy) authorized(req *http.Request) bool {
	if p.options.Username == "" && p.options.Password == "" {
		return true
	}
	if req == nil {
		return false
	}
	username, password, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	// Both comparisons always run so the result does not leak which half failed.
	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(p.options.Username))
	passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(p.options.Password))
	return userMatch&passMatch == 1
}

func parseProxyAuth(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	username, password, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	return username, password, true
}

func authRequiredResponse(req *http.Request) *http.Response {
	resp := goproxy.NewResponse(req, "text/plain", http.StatusProxyAuthRequired, "proxy authentication required\n")
	resp.Header.Set("Proxy-Authenticate", `Basic realm="nuclei dast proxy"`)
	// goproxy leaves the protocol version unset, which writes a "HTTP/0.0"
	// status line that strict clients reject when this is hijacked onto a raw
	// connection to answer CONNECT.
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	resp.Close = true
	return resp
}

// captureRequest renders the request as raw HTTP for the scanner, leaving the
// request that gets forwarded untouched.
func captureRequest(req *http.Request) (string, bool) {
	if req == nil || req.URL == nil {
		return "", false
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return "", false
	}
	// A body with no declared length, or one above the cap, is not mirrored at
	// all: fuzzing a large upload is not useful, buffering it would let proxied
	// traffic drive the scanner's memory use, and capturing only the headers
	// would hand the scanner a request that contradicts its own Content-Length.
	if hasBody(req) && (req.ContentLength < 0 || req.ContentLength > maxCapturedBodySize) {
		return "", false
	}

	body, err := bufferBody(req)
	if err != nil {
		gologger.Debug().Msgf("Could not buffer proxied request body: %s", err)
		return "", false
	}

	capture := req.Clone(req.Context())
	capture.Body = io.NopCloser(bytes.NewReader(body))
	capture.ContentLength = int64(len(body))
	// The proxy's own absolute-form request URI is not what the target sees.
	capture.RequestURI = ""
	// goproxy only strips hop-by-hop headers after this hook has run, so the
	// copy is sanitised here. The proxy credential in particular must never be
	// replayed to a target or written into scan output.
	stripHopByHopHeaders(capture.Header)

	dumped, err := httputil.DumpRequest(capture, true)
	if err != nil {
		gologger.Debug().Msgf("Could not capture proxied request: %s", err)
		return "", false
	}
	return string(dumped), true
}

func stripHopByHopHeaders(header http.Header) {
	for _, extra := range header.Values("Connection") {
		for _, name := range strings.Split(extra, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

func parseForwardProxy(raw string) (func(*http.Request) (*url.URL, error), error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, errors.Errorf("invalid dast proxy forward proxy %q", raw)
	}
	return http.ProxyURL(parsed), nil
}

func hasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody
}

// bufferBody reads the body and restores it on req so the request can still be
// forwarded after being mirrored.
func bufferBody(req *http.Request) ([]byte, error) {
	if !hasBody(req) {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxCapturedBodySize))
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func validateBinding(options *Options) error {
	host, _, err := net.SplitHostPort(options.Address)
	if err != nil {
		return errors.Wrapf(err, "invalid dast proxy address %q", options.Address)
	}
	if (options.Username == "") != (options.Password == "") {
		return errors.New("dast proxy auth needs both a username and a password")
	}
	if options.Username != "" || isLoopback(host) {
		return nil
	}
	// An unauthenticated proxy on a routable address is an open relay for
	// anyone who can reach it.
	return errors.Errorf("refusing to bind dast proxy to %q without authentication, pass -dast-proxy-auth user:pass or bind to localhost", options.Address)
}

func isLoopback(host string) bool {
	if host == "" {
		// A bare port binds every interface.
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// certCache memoises the leaf certificate minted for each intercepted host.
type certCache struct {
	certs sync.Map
}

func newCertCache() *certCache { return &certCache{} }

func (c *certCache) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	if cached, ok := c.certs.Load(hostname); ok {
		return cached.(*tls.Certificate), nil
	}
	cert, err := gen()
	if err != nil {
		return nil, err
	}
	actual, _ := c.certs.LoadOrStore(hostname, cert)
	return actual.(*tls.Certificate), nil
}

type proxyLogger struct{}

func (proxyLogger) Printf(format string, v ...any) {
	gologger.Debug().Msgf(format, v...)
}

// ParseAuth splits a user:pass credential pair as accepted on the command line.
func ParseAuth(value string) (username, password string, err error) {
	if value == "" {
		return "", "", nil
	}
	username, password, found := strings.Cut(value, ":")
	if !found || username == "" || password == "" {
		return "", "", errors.New("dast proxy auth must be in user:pass format")
	}
	return username, password, nil
}
