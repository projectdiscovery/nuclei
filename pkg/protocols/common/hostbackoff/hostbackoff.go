// Package hostbackoff paces requests to a host that signals it is being
// overloaded, so a scan slows down instead of being blocked outright.
//
// nuclei already skips a host after repeated transport errors
// (pkg/protocols/common/hosterrorscache), which is all or nothing. A target
// that answers 429, or starts answering 403 to everything, is asking for less
// traffic rather than none, and the useful response is to keep scanning it more
// slowly.
//
// The control rule follows shipped practice rather than anything novel: a
// per-host delay that grows multiplicatively while the host complains and
// decays while it is healthy, with the host's own Retry-After honoured when it
// asks for longer. Scrapy's AutoThrottle, Heritrix and Googlebot's crawl
// capacity limit all work this way, and the asymmetry (a bad response may only
// slow the scan, never speed it up) is what keeps one lucky success from
// undoing a backoff.
package hostbackoff

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gcache"
)

const (
	// DefaultStep is the delay applied the first time a host signals overload.
	DefaultStep = 250 * time.Millisecond
	// DefaultMax caps the per-host delay. Past this the host is better handled
	// by the host error cache, which skips it entirely.
	DefaultMax = 30 * time.Second
	// DefaultFactor grows the delay on each further complaint.
	DefaultFactor = 2.0
	// DefaultDecay shrinks the delay after a healthy response. It is far gentler
	// than the growth so that a scan recovers gradually rather than immediately
	// re-flooding a host that just recovered.
	DefaultDecay = 0.8
	// DefaultForbiddenStreak is how many consecutive 403s count as blocking. A
	// single 403 is ordinary (an endpoint the scan is not authorised for), but a
	// run of them usually means the host started refusing the scanner.
	DefaultForbiddenStreak = 5
	// DefaultMaxHosts bounds how many hosts are tracked at once, matching the
	// host error cache. A scan can carry millions of targets, so the state has
	// to be evictable; losing a host's entry only resets its delay, and the next
	// complaint earns it again.
	DefaultMaxHosts = 10000
)

// Config tunes the governor. The zero value is replaced by the defaults above.
type Config struct {
	Step            time.Duration
	Max             time.Duration
	Factor          float64
	Decay           float64
	ForbiddenStreak int
	MaxHosts        int
}

func (c *Config) applyDefaults() {
	if c.Step <= 0 {
		c.Step = DefaultStep
	}
	if c.Max <= 0 {
		c.Max = DefaultMax
	}
	if c.Factor <= 1 {
		c.Factor = DefaultFactor
	}
	if c.Decay <= 0 || c.Decay >= 1 {
		c.Decay = DefaultDecay
	}
	if c.ForbiddenStreak <= 0 {
		c.ForbiddenStreak = DefaultForbiddenStreak
	}
	if c.MaxHosts <= 0 {
		c.MaxHosts = DefaultMaxHosts
	}
}

type hostState struct {
	delay     time.Duration
	forbidden int
	// next is the earliest start time still free. Concurrent waits reserve
	// successive slots so a delay paces the host instead of holding a burst
	// and releasing it together.
	next time.Time
}

// Governor holds the per-host delay for a scan.
type Governor struct {
	cfg   Config
	mu    sync.Mutex
	hosts gcache.Cache[string, *hostState]
}

// New returns a governor using cfg, with unset fields defaulted.
func New(cfg Config) *Governor {
	cfg.applyDefaults()
	return &Governor{cfg: cfg, hosts: gcache.New[string, *hostState](cfg.MaxHosts).ARC().Build()}
}

// Delay reports the current pause for a host, zero when it looks healthy.
func (g *Governor) Delay(host string) time.Duration {
	if g == nil || host == "" {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if state, err := g.hosts.GetIFPresent(host); err == nil && state != nil {
		return state.delay
	}
	return 0
}

// Wait pauses until this caller’s slot on the host. Callers that arrive
// together take successive slots of the current delay, so they do not all
// wake at once. It returns the context error if the scan is cancelled while
// waiting, so a stop is not held up by a long backoff.
func (g *Governor) Wait(ctx context.Context, host string) error {
	if g == nil || host == "" {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	g.mu.Lock()
	state, err := g.hosts.GetIFPresent(host)
	if err != nil || state == nil || state.delay <= 0 {
		g.mu.Unlock()
		return nil
	}
	now := time.Now()
	start := state.next
	if start.Before(now) {
		start = now.Add(state.delay)
	}
	state.next = start.Add(state.delay)
	_ = g.hosts.Set(host, state)
	wait := start.Sub(now)
	g.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Observe feeds one response back to the governor. retryAfter is the parsed
// Retry-After header, zero when absent. err is the transport error, if any.
func (g *Governor) Observe(host string, statusCode int, retryAfter time.Duration, err error) {
	if g == nil || host == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	state, lookupErr := g.hosts.GetIFPresent(host)
	if lookupErr != nil || state == nil {
		state = &hostState{}
	}
	defer func() { _ = g.hosts.Set(host, state) }()

	if statusCode == http.StatusForbidden {
		state.forbidden++
	} else if healthyStatus(statusCode) {
		state.forbidden = 0
	}
	// A 403 that names Retry-After is the host asking for a wait. The streak
	// is only for bare 403s, which are often just an unauthorised endpoint.
	if statusCode == http.StatusForbidden && retryAfter > 0 && state.forbidden < g.cfg.ForbiddenStreak {
		state.forbidden = g.cfg.ForbiddenStreak
	}

	if !g.isBlocking(statusCode, err, state) {
		// Only a response that actually served (2xx/3xx) is evidence the host
		// recovered. A 404 or 500 is what most templates get back, and treating
		// it as healthy would wipe the delay on the next probe.
		if healthyStatus(statusCode) {
			state.delay = time.Duration(float64(state.delay) * g.cfg.Decay)
			if state.delay < g.cfg.Step {
				state.delay = 0
				state.next = time.Time{}
			}
		}
		return
	}

	next := state.delay
	if next <= 0 {
		next = g.cfg.Step
	} else {
		next = time.Duration(math.Min(float64(next)*g.cfg.Factor, float64(g.cfg.Max)))
	}
	// The host named a wait of its own; respect it when it is the longer of the
	// two, since it is the only figure that is not a guess.
	if retryAfter > next {
		next = retryAfter
	}
	if next > g.cfg.Max {
		next = g.cfg.Max
	}
	state.delay = next
}

// isBlocking reports whether a response means the host wants less traffic.
func (g *Governor) isBlocking(statusCode int, err error, state *hostState) bool {
	if err != nil {
		return true
	}
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	case http.StatusForbidden:
		return state.forbidden >= g.cfg.ForbiddenStreak
	}
	return false
}

// healthyStatus reports whether the host served a normal response. Template
// misses and server errors are not recovery.
func healthyStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest
}

// RetryAfter parses a Retry-After header, in either its delay-seconds or
// HTTP-date form. Delay-seconds is a non-negative decimal integer (RFC 9110);
// fractional and compound duration strings are rejected. A digit string that
// does not fit in a Duration saturates instead of being ignored. The result
// is zero when the header is absent or unparsable, and never a negative wait
// for a date already in the past.
func RetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if seconds, ok := delaySeconds(header); ok {
		return seconds
	}
	if when, err := http.ParseTime(header); err == nil {
		if wait := time.Until(when); wait > 0 {
			return wait
		}
	}
	return 0
}

// delaySeconds parses a Retry-After delay-seconds value. The boolean is false
// when header is not a decimal integer.
func delaySeconds(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	for i := 0; i < len(header); i++ {
		if header[i] < '0' || header[i] > '9' {
			return 0, false
		}
	}
	const maxDuration = time.Duration(1<<63 - 1)
	const maxSeconds = uint64(maxDuration / time.Second)
	seconds, err := strconv.ParseUint(header, 10, 64)
	if err != nil || seconds > maxSeconds {
		return maxDuration, true
	}
	return time.Duration(seconds) * time.Second, true
}
