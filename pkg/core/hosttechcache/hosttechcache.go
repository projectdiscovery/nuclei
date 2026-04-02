package hosttechcache

import (
	"strings"
	"sync"
	"github.com/projectdiscovery/gologger"
)

// TechHint represents a detected technology on a host that can be used
// to filter templates before execution.
type TechHint struct {
	// ServerHeader stores the original Server header value for logging purposes
	ServerHeader string
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
		if _, exists := c.hints[host]; exists {
			gologger.Debug().Msgf("[tech-filter] CLEARED hint for host '%s' (unrecognised Server header: '%s')",
				host, serverHeader)
		}
		delete(c.hints, host)
		return
	}

	gologger.Debug().Msgf("[tech-filter] RECORDED hint for host '%s' — Server: '%s' → required tags: %v",
		host, serverHeader, requiredTags)

	hint := &TechHint{
	ServerHeader: serverHeader,
	Tags:         make(map[string]struct{}, len(requiredTags)),
	}

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

// HasHint returns true if any hint (including "no recognised tech") has been
// recorded for this host, so we don't probe the same host twice.
func (c *HostTechCache) HasHint(host string) bool {
	c.mu.RLock()
	_, ok := c.hints[host]
	c.mu.RUnlock()
	return ok
}


// RecordNoServerHeader marks that we checked a host but found no Server header
func (c *HostTechCache) RecordNoServerHeader(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Create an empty TechHint to indicate we checked but found nothing
	c.hints[host] = &TechHint{
		ServerHeader: "",
		Tags:         make(map[string]struct{}),
	}
	gologger.Debug().Msgf("[tech-filter] RECORDED no Server header for host '%s'", host)
}

// GetServerHeader returns the detected server header for a host
func (c *HostTechCache) GetServerHeader(host string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	hint, exists := c.hints[host]
	if !exists || hint == nil {
		return ""
	}
	return hint.ServerHeader
}
