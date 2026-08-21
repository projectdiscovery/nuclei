package httpclientpool

import (
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

// A response that belonged to an earlier request on the connection is already in
// net/http's read buffer when the next request goes out, so readResponse's Peek(1)
// returns with no round trip -- often before the request has finished being written.
// A genuine response cannot cross the network faster than one round trip, so that gap
// identifies the wrong response exactly, for the request that received it.
//
// The baseline is the TCP handshake rather than previous response latencies: how long
// a server takes to answer swings by orders of magnitude between a cold and a cached
// response, so a latency baseline would flag the fast ones. The network floor does
// not move.
const suspectRTTFraction = 2

// host -> time.Duration of the fastest handshake seen for it.
var hostRTT sync.Map

// Counts responses found to belong to an earlier request on their connection.
var desyncedResponses atomic.Int64

// DesyncedResponses reports how many responses turned out to belong to an earlier
// request on their connection since the process started. Each one was retried, so it
// measures a condition that was handled, not results lost.
func DesyncedResponses() int64 {
	return desyncedResponses.Load()
}

// countDesyncedResponse is called by the request path when a probe fires.
func countDesyncedResponse() {
	desyncedResponses.Add(1)
}

// DesyncProbe collects one request's timing and reports whether the response it
// received had been left on the connection by an earlier one.
type DesyncProbe struct {
	host string

	mu           sync.Mutex
	connectStart time.Time
	connectRTT   time.Duration
	wroteHeaders time.Time
	firstByte    time.Time
	reused       bool
}

func NewDesyncProbe(host string) *DesyncProbe {
	return &DesyncProbe{host: host}
}

// Trace returns hooks to attach to the request context. httptrace composes with any
// trace already there, so this does not displace another one.
func (p *DesyncProbe) Trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.reused = info.Reused
		},
		ConnectStart: func(_, _ string) {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, err error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if err == nil && !p.connectStart.IsZero() {
				p.connectRTT = time.Since(p.connectStart)
			}
		},
		WroteHeaders: func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.wroteHeaders = time.Now()
		},
		GotFirstResponseByte: func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.firstByte = time.Now()
		},
	}
}

// Suspect reports whether the response belonged to an earlier request, and records
// what this request learned about the host's round trip time. A response on a fresh
// connection cannot be someone else's, so those only ever contribute a measurement.
//
// A verdict of true also counts towards DesyncedResponses, so call it once per
// request.
func (p *DesyncProbe) Suspect() bool {
	p.mu.Lock()
	reused, rtt := p.reused, p.connectRTT
	wroteHeaders, firstByte := p.wroteHeaders, p.firstByte
	p.mu.Unlock()

	if rtt > 0 {
		recordHostRTT(p.host, rtt)
	}

	if !reused || firstByte.IsZero() {
		return false
	}

	baseline, ok := hostRTTFor(p.host)
	if !ok {
		// Never measured a handshake for this host, so there is no floor to judge
		// against. Guessing one would risk disabling reuse for a healthy host.
		return false
	}

	if wroteHeaders.IsZero() {
		countDesyncedResponse()

		// The response arrived before this request's headers were even recorded as
		// written, which no genuine response can do.
		return true
	}

	if firstByte.Sub(wroteHeaders) >= baseline/suspectRTTFraction {
		return false
	}

	countDesyncedResponse()

	return true
}

func recordHostRTT(host string, rtt time.Duration) {
	key := desyncedHostKey(host)
	if key == "" {
		return
	}

	for {
		previous, loaded := hostRTT.LoadOrStore(key, rtt)
		if !loaded {
			return
		}

		fastest, ok := previous.(time.Duration)
		if !ok || rtt >= fastest {
			return
		}
		if hostRTT.CompareAndSwap(key, previous, rtt) {
			return
		}
	}
}

func hostRTTFor(host string) (time.Duration, bool) {
	key := desyncedHostKey(host)
	if key == "" {
		return 0, false
	}

	value, ok := hostRTT.Load(key)
	if !ok {
		return 0, false
	}

	rtt, ok := value.(time.Duration)

	return rtt, ok && rtt > 0
}
