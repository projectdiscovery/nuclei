package honeypotcache

import (
	"sync"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// CacheInterface defines the signature of the honeypot cache
type CacheInterface interface {
	Check(ctx *contextargs.Context) bool                   // return true if the host should be skipped (is a honeypot)
	MarkMatch(ctx *contextargs.Context, templateID string) // record a match for the host
}

// Cache is a cache for honeypot detection based on match threshold.
type Cache struct {
	mu           sync.Mutex
	MaxHostMatch int
	matches      gcache.Cache[string, *cacheItem]
}

type cacheItem struct {
	sync.RWMutex
	uniqueMatches map[string]struct{}
}

const DefaultMaxHostsCount = 10000

// New returns a new honeypot cache
func New(maxHostMatch, maxHostsCount int) *Cache {
	gc := gcache.New[string, *cacheItem](maxHostsCount).ARC().Build()

	return &Cache{
		matches:      gc,
		MaxHostMatch: maxHostMatch,
	}
}

// Check returns true if a host should be skipped as it has matched too many templates.
func (c *Cache) Check(ctx *contextargs.Context) bool {
	if c.MaxHostMatch <= 0 {
		return false
	}
	key := ctx.MetaInput.Input
	item, err := c.matches.GetIFPresent(key)
	if err != nil {
		return false
	}

	item.RLock()
	defer item.RUnlock()

	if len(item.uniqueMatches) >= c.MaxHostMatch {
		gologger.Verbose().Msgf("Skipping %s as it reached the maximum match threshold (%d), potential honeypot detected", key, c.MaxHostMatch)
		return true
	}

	return false
}

// MarkMatch records a match for the host and returns true if it just reached the threshold
func (c *Cache) MarkMatch(ctx *contextargs.Context, templateID string) {
	if c.MaxHostMatch <= 0 {
		return
	}
	key := ctx.MetaInput.Input

	c.mu.Lock()
	item, err := c.matches.GetIFPresent(key)
	if err != nil {
		item = &cacheItem{
			uniqueMatches: make(map[string]struct{}),
		}
		_ = c.matches.Set(key, item)
	}
	c.mu.Unlock()

	item.Lock()
	defer item.Unlock()

	item.uniqueMatches[templateID] = struct{}{}
}
