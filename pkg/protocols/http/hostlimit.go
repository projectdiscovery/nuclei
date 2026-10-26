package http

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostlimit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
)

// admitToEndpoint waits for room on the request's endpoint when adaptive
// concurrency is on. Race requests are exempt: they must leave together.
//
// The wait uses scanCtx, not the request's own context: the request deadline
// (the HTTP timeout) must not run while the request is still queued, or a
// queued request could time out before it is sent and be counted as a host
// error. Time spent waiting is added back to the request deadline. The returned
// release function undoes that and must be called once the request is done.
func (request *Request) admitToEndpoint(scanCtx context.Context, req *generatedRequest) (*hostlimit.Ticket, func(), error) {
	noop := func() {}
	if request.options == nil || request.options.HostLimit == nil || req == nil || req.request == nil || req.request.Request == nil {
		return nil, noop, nil
	}
	if req.original != nil && req.original.Race {
		return nil, noop, nil
	}
	start := time.Now()
	ticket, err := request.options.HostLimit.Acquire(scanCtx, endpointKey(req.request.Request.URL))
	if err != nil {
		return nil, noop, err
	}
	waited := time.Since(start)
	reqCtx := req.request.Context()
	deadline, ok := reqCtx.Deadline()
	if !ok || waited <= 0 {
		return ticket, noop, nil
	}
	// Keep the request's values (custom IP, timeout markers) but move its
	// deadline back by the time spent queued. The scan's cancellation still
	// stops the request.
	extended, cancel := context.WithDeadlineCause(context.WithoutCancel(reqCtx), deadline.Add(waited), ErrHttpEngineRequestDeadline)
	stop := context.AfterFunc(scanCtx, cancel)
	req.request.Request = req.request.Request.WithContext(extended)
	return ticket, func() { stop(); cancel() }, nil
}

// releaseEndpoint returns the slot and tells the limiter how the request went.
func (request *Request) releaseEndpoint(ticket *hostlimit.Ticket, req *generatedRequest, resp *http.Response, err error) {
	if ticket == nil {
		return
	}
	custom := request.hasCustomTimeout(req)
	o := hostlimit.Outcome{Latency: ticket.Since()}
	switch {
	case err != nil:
		// A timeout the template asked for is not the endpoint struggling.
		o.Overload = !custom && hostlimit.IsOverload(err)
	case resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable):
		o.Overload = true
	default:
		o.Sample = !custom
	}
	ticket.Release(o)
}

// hasCustomTimeout reports whether the template set its own timeout, which
// means its latency is slow by design and says nothing about the endpoint.
func (request *Request) hasCustomTimeout(req *generatedRequest) bool {
	if request.connConfiguration != nil && (request.connConfiguration.NoTimeout || request.connConfiguration.Connection != nil && request.connConfiguration.Connection.CustomMaxTimeout > 0) {
		return true
	}
	if req != nil && req.request != nil {
		if _, ok := req.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout); ok {
			return true
		}
	}
	return false
}

// endpointKey is host:port with the scheme's default port filled in.
func endpointKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https", "wss":
			port = "443"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}
