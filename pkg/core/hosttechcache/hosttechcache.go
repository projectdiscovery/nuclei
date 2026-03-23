package hosttechcache

import (
	"strings"
	"sync"
)

// TechHint represents a detected technology on a host that can be used
// to filter templates before execution.
type TechHint struct {
	// Tags is the set of template tags that are REQUIRED for this host.
	// A template is skipped unless it contains at least one of these tags,
	// or the set is empty (meaning: no filtering).
	Tags map[string]struct{}
}

// HostTechCache stores per-host technology hints derived from early HTTP
// responses (e.g. the Server: header).  It is safe for concurrent use.
type HostTechCache struct {
	mu    sync.RWMutex
	hints map[string]*TechHint // keyed by normalised host (scheme+host)
}

// NewHostTechCache returns an initialised HostTechCache.
func NewHostTechCache() *HostTechCache {
	return &HostTechCache{hints: make(map[string]*TechHint)}
}

// RecordServerHeader inspects a raw Server header value and, if it contains
// a known technology keyword, records a tag requirement for that host.
//
// Currently understood keywords → required tag:
//
//	"apache" → "apache"
//
// The mapping is intentionally simple and lowercase-compared so that
// "Apache/2.4.51 (Unix)" and "apache" both resolve to the same hint.
func (c *HostTechCache) RecordServerHeader(host, serverHeader string) {
	lower := strings.ToLower(serverHeader)

	var requiredTags []string
	if strings.Contains(lower, "apache") {
		requiredTags = append(requiredTags, "apache")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(requiredTags) == 0 {
		// Unrecognised server — clear any existing hint so the old
		// technology detection doesn't persist after a redirect/overwrite.
		delete(c.hints, host)
		return
	}

	hint := &TechHint{Tags: make(map[string]struct{}, len(requiredTags))}
	for _, t := range requiredTags {
		hint.Tags[t] = struct{}{}
	}
	c.hints[host] = hint
}

// ShouldSkipTemplate returns true when the cache has a hint for the given host
// AND the template's tags contain none of the required tags.
//
// If there is no hint for the host the function always returns false (no skip).
func (c *HostTechCache) ShouldSkipTemplate(host string, templateTags []string) bool {
	c.mu.RLock()
	hint, ok := c.hints[host]
	c.mu.RUnlock()

	if !ok || len(hint.Tags) == 0 {
		return false // no information → don't skip
	}

	for _, tag := range templateTags {
		if _, required := hint.Tags[strings.ToLower(tag)]; required {
			return false // template has at least one matching tag → keep it
		}
	}
	return true // no matching tag found → skip
}