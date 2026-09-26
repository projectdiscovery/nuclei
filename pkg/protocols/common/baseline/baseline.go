// Package baseline implements per-host catch-all detection used to lower the
// confidence of likely false-positive matches.
//
// Many hosts answer every request with the same "catch-all" page (custom 404s,
// SPA shells, WAF interstitials, login walls). Templates whose matchers fire on
// such a page produce false positives. The approach here follows the black-box
// scanner literature (x8, Metasploit Differential, ReScan): learn the host's
// response to a request that almost certainly does not exist, then check whether
// a template's matchers ALSO fire on that baseline. Unlike body-diffing schemes,
// replaying the operators is binary and robust: if a matcher matches a known
// non-existent path, the detection is not specific to the real target.
package baseline

import "sync"

// maxHosts bounds the number of cached baselines to keep memory predictable on
// very large scans; beyond it, baselines are still fetched but not retained.
const maxHosts = 10000

// Map is a learned baseline: the DSL field map produced from the control
// response, suitable for replaying a template's compiled operators against.
type Map = map[string]interface{}

// Cache learns and stores a per-host catch-all baseline so it can be replayed
// against every template without re-fetching. Each host is fetched at most once,
// even under concurrent access.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	once sync.Once
	data Map
	ok   bool
}

// New returns an empty baseline cache.
func New() *Cache {
	return &Cache{entries: make(map[string]*entry)}
}

// GetOrFetch returns the baseline for host, invoking fetch exactly once per host
// to learn it. fetch should return the DSL map of the control response; a nil
// map or error marks the host as having no usable baseline. The second return
// value reports whether a usable baseline is available.
func (c *Cache) GetOrFetch(host string, fetch func() (Map, error)) (Map, bool) {
	if c == nil || host == "" {
		return nil, false
	}

	c.mu.Lock()
	e, found := c.entries[host]
	if !found {
		// Don't grow the cache without bound. Over the cap we fetch directly so
		// detection still works, we just don't retain the baseline.
		if len(c.entries) >= maxHosts {
			c.mu.Unlock()
			data, err := fetch()
			return data, err == nil && data != nil
		}
		e = &entry{}
		c.entries[host] = e
	}
	c.mu.Unlock()

	e.once.Do(func() {
		data, err := fetch()
		if err == nil && data != nil {
			e.data = data
			e.ok = true
		}
	})
	return e.data, e.ok
}
