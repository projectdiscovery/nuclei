package testing

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"

	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/martian/v3"
	martianlog "github.com/projectdiscovery/martian/v3/log"
	"github.com/projectdiscovery/proxify"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	httputils "github.com/projectdiscovery/utils/http"
)

// ProxyServer is an intercepting proxy launched through nuclei
// using proxify for logging requests and responses.
//
// This is intended for unit testing of http templates in nuclei.
type ProxyServer struct {
	ListenAddr string

	intercepted []RequestResponsePair
	mutex       *sync.RWMutex

	proxy   *proxify.Proxy
	tempdir string
}

// RequestResponsePair is a pair of request and response
type RequestResponsePair struct {
	Request  string `json:"request" yaml:"request"`
	Response string `json:"response" yaml:"response"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

func responsePairFromResp(resp *http.Response) RequestResponsePair {
	if resp.Request.Method == http.MethodConnect {
		return RequestResponsePair{}
	}

	save := resp.Body
	savecl := resp.ContentLength

	var err error
	if resp.Body != nil {
		save, resp.Body, err = drainBody(resp.Body)
		if err != nil {
			return RequestResponsePair{}
		}
	}
	chain := httputils.NewResponseChain(resp, -1)
	defer chain.Close()

	if err := chain.Fill(); err != nil {
		log.Printf("[error] [proxy] Could not fill response chain: %s\n", err)
		return RequestResponsePair{}
	}
	resp.Body = save
	resp.ContentLength = savecl

	if !chain.Has() {
		return RequestResponsePair{}
	}
	respDump := chain.FullResponse()

	return RequestResponsePair{
		Response: respDump.String(),
	}
}

// Intercepted returns the intercepted requests and responsesq
func (p *ProxyServer) Intercepted() []RequestResponsePair {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.intercepted
}

// AddIntercepted adds a new request response pair to the intercepted list
func (p *ProxyServer) AddIntercepted(pair RequestResponsePair) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.intercepted = append(p.intercepted, pair)
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer() (*ProxyServer, error) {
	ps := &ProxyServer{
		mutex: &sync.RWMutex{},
	}

	onRequestFunc := func(req *http.Request, ctx *martian.Context) error {
		dumped, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			return nil
		}
		ctx.Set(ctx.ID(), RequestResponsePair{
			Request: string(dumped),
		})
		ctx.Set("user-data", types.UserData{})
		return nil
	}

	onResponseFunc := func(resp *http.Response, ctx *martian.Context) error {
		pair := responsePairFromResp(resp)
		if pair.Response == "" {
			return nil
		}
		req, ok := ctx.Get(ctx.ID())
		if !ok {
			log.Printf("[error] [proxy] Could not get request from context\n")
			return nil
		}
		valid, ok := req.(RequestResponsePair)
		if !ok {
			log.Printf("[error] [proxy] Could not validate request from context\n")
			return nil
		}
		pair.Request = valid.Request
		pair.Protocol = "http"
		ps.AddIntercepted(pair)
		return nil
	}
	_, _ = onRequestFunc, onResponseFunc

	tempdir, err := os.MkdirTemp("", "proxify-*")
	if err != nil {
		return nil, err
	}
	ps.tempdir = tempdir

	err = certs.LoadCerts(tempdir)
	if err != nil {
		return nil, err
	}

	hostname := "127.0.0.1"
	port, err := freeport.GetFreePort(hostname, freeport.TCP)
	if err != nil {
		return nil, err
	}
	ps.ListenAddr = fmt.Sprintf("%s:%d", hostname, port.Port)

	martianlog.SetLogger(&noopMartianLogger{})
	opts := &proxify.Options{
		OutputJsonl:                 true,
		MaxSize:                     math.MaxInt,
		Verbosity:                   types.VerbosityDefault,
		CertCacheSize:               256,
		Directory:                   tempdir,
		ListenAddrHTTP:              ps.ListenAddr,
		OnRequestCallback:           onRequestFunc,
		OnResponseCallback:          onResponseFunc,
		UpstreamProxyRequestsNumber: 1,
		Elastic:                     &elastic.Options{},
		Kafka:                       &kafka.Options{},
	}
	proxy, err := proxify.NewProxy(opts)
	if err != nil {
		return nil, err
	}
	ps.proxy = proxy

	go func() {
		err = proxy.Run()
		if err != nil {
			log.Printf("[error] [proxy] Could not run proxy: %s\n", err)
		}
	}()
	return ps, nil
}

type noopMartianLogger struct{}

func (l *noopMartianLogger) Infof(format string, args ...interface{})  {}
func (l *noopMartianLogger) Debugf(format string, args ...interface{}) {}
func (l *noopMartianLogger) Errorf(format string, args ...interface{}) {}

func (p *ProxyServer) Close() {
	_ = os.RemoveAll(p.tempdir)
	p.proxy.Stop()
}

// from net/http/httputil.DumpResponse
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err = b.Close(); err != nil {
		return nil, b, err
	}
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}
