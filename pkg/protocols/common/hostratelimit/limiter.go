package hostratelimit

import (
	"fmt"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

// GetPerHostRateLimiter gets or creates a rate limiter for a specific host
// Returns nil if per-host rate limiting is not enabled
func GetPerHostRateLimiter(options *types.Options, hostname string) (*ratelimit.Limiter, error) {
	if !options.PerHostRateLimit {
		return nil, nil
	}

	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}

	dialers.Lock()
	if dialers.PerHostRateLimitPool == nil {
		poolSize := options.PerHostRateLimitPoolSize
		if poolSize == 0 {
			poolSize = 1024
		} else if poolSize < 0 {
			// expirable.LRU uses zero as its unbounded mode. This is useful for
			// scan-persistent embedders that must never refresh a host budget
			// merely because many other hosts were visited.
			poolSize = 0
		}
		// Keep entries for the entire scan duration - no TTL-based eviction during scan
		// so all hosts are tracked throughout the entire scan, even for very long scans
		dialers.PerHostRateLimitPool = NewPerHostRateLimitPool(poolSize, 24*time.Hour, 24*time.Hour, options)
	}
	poolAny := dialers.PerHostRateLimitPool
	dialers.Unlock()

	pool, ok := poolAny.(*PerHostRateLimitPool)
	if !ok || pool == nil {
		return nil, nil
	}

	return pool.GetOrCreate(hostname)
}

// RecordPerHostRateLimitRequest records a request for pps stats calculation
func RecordPerHostRateLimitRequest(options *types.Options, hostname string) {
	if !options.PerHostRateLimit || hostname == "" {
		return
	}

	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return
	}

	dialers.Lock()
	poolAny := dialers.PerHostRateLimitPool
	dialers.Unlock()

	pool, ok := poolAny.(*PerHostRateLimitPool)
	if !ok || pool == nil {
		return
	}

	pool.RecordRequest(hostname)
}
