// Package hostlimit bounds how many requests are in flight to one endpoint
// (host:port) at a time, and adapts that bound to what the endpoint can take.
//
// A fixed template concurrency cannot be right for every target. Measured on a
// WordPress server: 50 concurrent templates were fast and lossless, 100 lost 13
// of 17 findings to timeouts without any visible error, and 10 were twice as
// slow. On an nginx server the same 100 was harmless. The safe concurrency is a
// property of the target, so it is measured while the scan runs.
//
// The control rule is the one TCP congestion control and adaptive concurrency
// limiters use: grow the limit slowly while the endpoint stays healthy, cut it
// at once when it shows strain. Healthy means the median latency of ordinary
// requests stays close to the endpoint's own baseline and no overload errors
// (timeouts, resets, 429, 503) appear. Requests that are slow by design, such as
// time-based checks with a custom timeout, are admitted and counted, but they do
// not feed the latency signal.
package hostlimit

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config tunes the limiter. Zero fields take the defaults.
type Config struct {
	// Initial is the limit an endpoint starts with.
	Initial int
	// Min and Max bound the limit.
	Min, Max int
	// Tolerance is how much the window median latency may exceed the baseline
	// before the endpoint counts as strained (2 = twice the baseline).
	Tolerance float64
	// Window is how many latency samples one control decision uses.
	Window int
}

func (c *Config) defaults() {
	if c.Initial <= 0 {
		c.Initial = 16
	}
	if c.Min <= 0 {
		c.Min = 2
	}
	if c.Max <= 0 {
		c.Max = 256
	}
	if c.Max < c.Min {
		c.Max = c.Min
	}
	if c.Initial < c.Min {
		c.Initial = c.Min
	}
	if c.Initial > c.Max {
		c.Initial = c.Max
	}
	if c.Tolerance <= 1 {
		c.Tolerance = 2
	}
	if c.Window <= 0 {
		c.Window = 16
	}
}

// Limiter holds one adaptive limit per endpoint for a scan.
type Limiter struct {
	cfg       Config
	mu        sync.Mutex
	endpoints map[string]*endpoint
}

// New returns a limiter with cfg, unset fields defaulted.
func New(cfg Config) *Limiter {
	cfg.defaults()
	return &Limiter{cfg: cfg, endpoints: make(map[string]*endpoint)}
}

// Outcome describes how one admitted request ended.
type Outcome struct {
	// Overload is set when the endpoint showed strain: a timeout, a reset, a
	// refused connection on an endpoint that was answering, or a 429/503.
	Overload bool
	// Sample is set when the latency is a fair health signal (an ordinary
	// request with the default timeout).
	Sample bool
	// Latency is the time from admission to the response headers.
	Latency time.Duration
}

// Ticket is one admission. Release it exactly once.
type Ticket struct {
	e     *endpoint
	start time.Time
	once  sync.Once
}

// Acquire waits until the endpoint has room, or ctx ends.
func (l *Limiter) Acquire(ctx context.Context, key string) (*Ticket, error) {
	if l == nil || key == "" {
		return &Ticket{}, nil
	}
	e := l.endpoint(key)
	if err := e.acquire(ctx); err != nil {
		return nil, err
	}
	return &Ticket{e: e, start: time.Now()}, nil
}

// Since returns the time elapsed since admission.
func (t *Ticket) Since() time.Duration {
	if t == nil || t.e == nil {
		return 0
	}
	return time.Since(t.start)
}

// Release returns the slot and feeds the outcome to the endpoint's control loop.
func (t *Ticket) Release(o Outcome) {
	if t == nil || t.e == nil {
		return
	}
	t.once.Do(func() { t.e.release(o) })
}

// Limit reports the current limit of an endpoint (tests and stats).
func (l *Limiter) Limit(key string) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	e, ok := l.endpoints[key]
	l.mu.Unlock()
	if !ok {
		return l.cfg.Initial
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return int(e.limit)
}

func (l *Limiter) endpoint(key string) *endpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.endpoints[key]
	if !ok {
		e = &endpoint{cfg: &l.cfg, limit: float64(l.cfg.Initial)}
		l.endpoints[key] = e
	}
	return e
}

type endpoint struct {
	cfg *Config
	mu  sync.Mutex

	limit    float64
	inflight int
	waiters  []chan struct{}

	samples   []time.Duration
	overloads int
	peakUse   int
	baseline  time.Duration
}

func (e *endpoint) acquire(ctx context.Context) error {
	e.mu.Lock()
	if e.inflight < int(e.limit) && len(e.waiters) == 0 {
		e.inflight++
		e.notePeak()
		e.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	e.waiters = append(e.waiters, ch)
	e.mu.Unlock()

	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		e.mu.Lock()
		for i, w := range e.waiters {
			if w == ch {
				e.waiters = append(e.waiters[:i], e.waiters[i+1:]...)
				e.mu.Unlock()
				return ctx.Err()
			}
		}
		e.mu.Unlock()
		// The slot was handed over while ctx ended; give it back.
		e.release(Outcome{})
		return ctx.Err()
	}
}

// notePeak records how much of the limit the endpoint actually used in the
// current window. Must hold e.mu.
func (e *endpoint) notePeak() {
	if e.inflight > e.peakUse {
		e.peakUse = e.inflight
	}
}

func (e *endpoint) release(o Outcome) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.inflight--
	if o.Overload {
		e.overloads++
	}
	if o.Sample && o.Latency > 0 {
		e.samples = append(e.samples, o.Latency)
	}
	if o.Overload || len(e.samples) >= e.cfg.Window {
		e.adjust()
	}
	e.wake()
}

// adjust runs one control decision. Must hold e.mu.
func (e *endpoint) adjust() {
	minL, maxL := float64(e.cfg.Min), float64(e.cfg.Max)
	defer func() {
		e.samples = e.samples[:0]
		e.overloads = 0
		e.peakUse = e.inflight
	}()

	if e.overloads > 0 {
		e.limit = clamp(e.limit*0.5, minL, maxL)
		return
	}
	if len(e.samples) == 0 {
		return
	}
	median := medianOf(e.samples)
	switch {
	case e.baseline == 0 || median < e.baseline:
		e.baseline = median
	default:
		// Let the baseline drift up slowly, so one lucky early window does not
		// pin the limit forever.
		e.baseline += (median - e.baseline) / 50
	}
	if float64(median) > float64(e.baseline)*e.cfg.Tolerance {
		e.limit = clamp(e.limit*0.8, minL, maxL)
		return
	}
	// Grow only when the limit was the bottleneck; an idle endpoint keeps its
	// limit, so a later burst cannot arrive at an untested size.
	if float64(e.peakUse) >= e.limit-1 {
		e.limit = clamp(e.limit+2, minL, maxL)
	}
}

// wake hands free slots to waiters in arrival order. Must hold e.mu.
func (e *endpoint) wake() {
	for len(e.waiters) > 0 && e.inflight < int(e.limit) {
		ch := e.waiters[0]
		e.waiters = e.waiters[1:]
		e.inflight++
		e.notePeak()
		close(ch)
	}
}

func medianOf(s []time.Duration) time.Duration {
	c := append([]time.Duration(nil), s...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// IsOverload reports whether a transport error suggests the endpoint is
// overloaded rather than the scan stopping: a timeout, a reset, a refused
// connection or a truncated reply. A cancelled context is not overload.
func IsOverload(err error) bool {
	if err == nil || stderrors.Is(err, context.Canceled) {
		return false
	}
	var ne net.Error
	if stderrors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if stderrors.Is(err, context.DeadlineExceeded) || stderrors.Is(err, syscall.ECONNRESET) ||
		stderrors.Is(err, syscall.ECONNREFUSED) || stderrors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection refused")
}
