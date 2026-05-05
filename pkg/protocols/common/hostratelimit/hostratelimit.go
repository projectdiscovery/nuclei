// Package hostratelimit provides a per-host rate limiter pool with bounded
// eviction, mirroring the per-host HTTP client pool model.
//
// Each host gets its own *ratelimit.Limiter on first use, lazily. Idle entries
// are reclaimed by a background sweep, and a hard cap evicts the least-recently
// used entry when the pool grows beyond MaxHosts so worst-case memory is
// bounded on long-running scans across many targets.
//
// Unlike the *retryablehttp.Client pool, each *ratelimit.Limiter runs an
// internal goroutine, so eviction MUST call Stop() to release it - otherwise
// a long scan that touches many short-lived hostnames would leak one
// goroutine per unique host. mapsutil.SyncLockMap.WithEviction has no
// on-evict callback, hence this small bespoke pool.
package hostratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

const (
	// DefaultInactivity is how long an idle per-host limiter is retained
	// before the background sweep reclaims it.
	DefaultInactivity = 90 * time.Second
	// DefaultSweepInterval controls how often the background sweep runs.
	DefaultSweepInterval = 30 * time.Second
	// DefaultMaxHosts caps the pool to bound worst-case memory across very
	// large input sets. When exceeded, the LRU entry is evicted on insert.
	DefaultMaxHosts = 4096
)

// Options configures a Pool.
type Options struct {
	// MaxCount is the bucket size for each per-host limiter (e.g. 60).
	// Required: a Pool with MaxCount == 0 is treated as disabled and
	// Take/Get become no-ops.
	MaxCount uint
	// Duration is the bucket refill interval (e.g. time.Minute).
	// Required when MaxCount > 0.
	Duration time.Duration
	// Inactivity controls how long an idle per-host limiter is retained
	// before the sweep reclaims it. Defaults to DefaultInactivity.
	Inactivity time.Duration
	// SweepInterval controls how often the background sweep runs.
	// Defaults to DefaultSweepInterval.
	SweepInterval time.Duration
	// MaxHosts caps the number of live limiters retained at once. When
	// the pool would exceed this size, the LRU entry is evicted (and
	// Stop()-ed) on insert. Defaults to DefaultMaxHosts.
	MaxHosts int
}

// Disabled reports whether this options configuration produces a no-op pool.
func (o Options) Disabled() bool {
	return o.MaxCount == 0 || o.Duration == 0
}

func (o *Options) applyDefaults() {
	if o.Inactivity <= 0 {
		o.Inactivity = DefaultInactivity
	}
	if o.SweepInterval <= 0 {
		o.SweepInterval = DefaultSweepInterval
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = DefaultMaxHosts
	}
}

// Pool is a per-host rate limiter pool.
//
// The zero value is not usable; use NewPool. A nil *Pool is valid and behaves
// as a no-op limiter, so callers can use the same code path whether or not
// per-host limiting is enabled.
type Pool struct {
	ctx    context.Context
	cancel context.CancelFunc
	opts   Options

	mu      sync.Mutex
	entries map[string]*entry
	// stoppedLimiters is incremented every time Stop() is called on a
	// per-host limiter (eviction or shutdown). Exposed for tests; the
	// production caller does not need it.
	stoppedLimiters uint64

	stopOnce sync.Once
	doneCh   chan struct{}
}

type entry struct {
	limiter    *ratelimit.Limiter
	lastAccess time.Time
}

// NewPool constructs a Pool. If opts.Disabled() reports true a nil Pool is
// returned, which is valid and acts as a no-op.
func NewPool(ctx context.Context, opts Options) *Pool {
	if opts.Disabled() {
		return nil
	}
	opts.applyDefaults()

	pctx, cancel := context.WithCancel(ctx)
	p := &Pool{
		ctx:     pctx,
		cancel:  cancel,
		opts:    opts,
		entries: make(map[string]*entry),
		doneCh:  make(chan struct{}),
	}
	go p.sweepLoop()
	return p
}

// Take acquires one token from the per-host limiter for host. If host is
// empty or the pool is nil/disabled, Take is a no-op.
func (p *Pool) Take(host string) {
	if p == nil || host == "" {
		return
	}
	l := p.getOrCreate(host)
	if l != nil {
		l.Take()
	}
}

// Get returns the *ratelimit.Limiter associated with host, creating it on
// first use. Returns nil if the pool is nil/disabled or host is empty.
//
// Most callers should prefer Take(host) which combines lookup and
// acquisition; Get is exposed for tests and rare callers that need the
// raw limiter (e.g. to query GetLimit()).
func (p *Pool) Get(host string) *ratelimit.Limiter {
	if p == nil || host == "" {
		return nil
	}
	return p.getOrCreate(host)
}

// Len returns the number of live per-host limiters. Useful for tests and
// metrics; a nil Pool reports 0.
func (p *Pool) Len() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// Stop drains all per-host limiters and stops the background sweep. Safe to
// call multiple times and on a nil Pool.
func (p *Pool) Stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		p.cancel()
		<-p.doneCh

		p.mu.Lock()
		defer p.mu.Unlock()
		for k, e := range p.entries {
			e.limiter.Stop()
			p.stoppedLimiters++
			delete(p.entries, k)
		}
	})
}

func (p *Pool) getOrCreate(host string) *ratelimit.Limiter {
	now := time.Now()

	p.mu.Lock()
	if e, ok := p.entries[host]; ok {
		e.lastAccess = now
		l := e.limiter
		p.mu.Unlock()
		return l
	}

	// Enforce hard cap before insert so the map size never exceeds
	// MaxHosts. We pick the LRU victim under the lock and Stop() it
	// outside the lock to keep the critical section short.
	var victim *ratelimit.Limiter
	if len(p.entries) >= p.opts.MaxHosts {
		var (
			oldestKey  string
			oldestTime time.Time
			first      = true
		)
		for k, e := range p.entries {
			if first || e.lastAccess.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.lastAccess
				first = false
			}
		}
		if oldestKey != "" {
			victim = p.entries[oldestKey].limiter
			delete(p.entries, oldestKey)
			p.stoppedLimiters++
		}
	}

	l := ratelimit.New(p.ctx, p.opts.MaxCount, p.opts.Duration)
	p.entries[host] = &entry{limiter: l, lastAccess: now}
	p.mu.Unlock()

	if victim != nil {
		victim.Stop()
	}
	return l
}

// sweepLoop periodically reclaims per-host limiters that have been inactive
// for opts.Inactivity. Each evicted limiter is Stop()-ed to release its
// internal goroutine.
func (p *Pool) sweepLoop() {
	defer close(p.doneCh)

	ticker := time.NewTicker(p.opts.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.evictIdle(time.Now())
		}
	}
}

// evictIdle removes entries whose lastAccess is older than now-Inactivity.
// Stops are performed outside the lock.
func (p *Pool) evictIdle(now time.Time) {
	cutoff := now.Add(-p.opts.Inactivity)

	var stops []*ratelimit.Limiter
	p.mu.Lock()
	for k, e := range p.entries {
		if e.lastAccess.Before(cutoff) {
			stops = append(stops, e.limiter)
			delete(p.entries, k)
			p.stoppedLimiters++
		}
	}
	p.mu.Unlock()

	for _, l := range stops {
		l.Stop()
	}
}
