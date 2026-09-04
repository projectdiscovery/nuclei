package httpclientpool

import (
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Counts responses found to belong to an earlier request on their connection.
var desyncedResponses atomic.Int64

// DesyncedResponses reports how many responses turned out to belong to an earlier
// request on their connection since the process started. Recovery is attempted for
// every detection, but may still fail if the body cannot be replayed or dialing fails.
func DesyncedResponses() int64 {
	return desyncedResponses.Load()
}

// countDesyncedResponse is called by the request path when a probe fires.
func countDesyncedResponse() {
	desyncedResponses.Add(1)
}

// DesyncProbe compares response timing on a reused HTTP/1.x connection with the
// fastest recent connection setup observed for the same host.
type DesyncProbe struct {
	host      string
	baselines *protocolstate.ExpiringDurationMap

	mu           sync.Mutex
	connectStart time.Time
	gotConn      time.Time
	wroteHeaders time.Time
	firstByte    time.Time
	reused       bool
}

const (
	desyncBaselineTTL = 15 * time.Minute
	// Sub-millisecond scheduling noise dominates very short loopback/LAN RTTs.
	// Skipping those baselines favors a miss over quarantining a healthy host.
	minDesyncBaseline = 2 * time.Millisecond
)

func NewDesyncProbe(host string, baselines *protocolstate.ExpiringDurationMap) *DesyncProbe {
	return &DesyncProbe{host: desyncedHostKey(host), baselines: baselines}
}

// Trace returns hooks to attach to the request context. httptrace composes with any
// trace already there, so this does not displace another one.
func (p *DesyncProbe) Trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			p.mu.Lock()
			p.reused = info.Reused
			p.gotConn = time.Now()
			p.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			p.mu.Lock()
			p.connectStart = time.Now()
			p.mu.Unlock()
		},
		ConnectDone: func(_, _ string, err error) {
			p.mu.Lock()
			start := p.connectStart
			p.mu.Unlock()
			if err == nil && !start.IsZero() {
				p.baselines.StoreMin(p.host, time.Since(start), desyncBaselineTTL)
			}
		},
		WroteHeaders: func() {
			p.mu.Lock()
			p.wroteHeaders = time.Now()
			p.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			p.mu.Lock()
			if p.firstByte.IsZero() {
				p.firstByte = time.Now()
			}
			p.mu.Unlock()
		},
	}
}

// Suspect reports whether a reused connection returned a response in less than
// half the fastest observed connection setup time for the host. This is a
// conservative symptom check: without transport changes, HTTP/1.x cannot prove
// that a well-formed response belongs to the current request.
func (p *DesyncProbe) Suspect() bool {
	p.mu.Lock()
	reused := p.reused
	gotConn := p.gotConn
	wroteHeaders := p.wroteHeaders
	firstByte := p.firstByte
	p.mu.Unlock()

	if !reused || firstByte.IsZero() {
		return false
	}
	baseline, ok := p.baselines.Load(p.host)
	if !ok || baseline < minDesyncBaseline {
		return false
	}

	anchor := wroteHeaders
	if anchor.IsZero() || firstByte.Before(anchor) {
		anchor = gotConn
	}
	if anchor.IsZero() {
		return false
	}
	elapsed := firstByte.Sub(anchor)
	return elapsed >= 0 && elapsed < baseline/2
}
