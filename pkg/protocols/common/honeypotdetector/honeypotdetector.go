package honeypotdetector

import (
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/projectdiscovery/gologger"
)

// DefaultMaxHosts is the default maximum number of hosts to track
const DefaultMaxHosts = 10000

// DefaultThreshold is the default number of distinct template matches to flag as honeypot
const DefaultThreshold = 10

// Detector tracks template match density per host to identify honeypots.
// Honeypots often serve responses that match many nuclei templates at once,
// which is a clear indicator of a fake/trap host designed to fool scanners.
type Detector struct {
	cache     *lru.Cache[string, *hostEntry]
	threshold int
	verbose   bool
	mu        sync.RWMutex

	// Statistics
	honeypotCount atomic.Int32
}

// hostEntry tracks distinct template IDs for a single host
type hostEntry struct {
	templates map[string]struct{}
	flagged   bool
	mu        sync.Mutex
}

// New creates a new honeypot detector with configurable threshold and max hosts.
// threshold: number of distinct template matches to trigger honeypot detection
// maxHosts: maximum number of hosts to track (uses LRU eviction)
func New(threshold, maxHosts int) *Detector {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}

	cache, _ := lru.New[string, *hostEntry](maxHosts)

	return &Detector{
		cache:     cache,
		threshold: threshold,
	}
}

// SetVerbose enables verbose logging
func (d *Detector) SetVerbose(verbose bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.verbose = verbose
}

// RecordMatch records a template match for a host and returns true if the host
// is now flagged as a honeypot (either newly flagged or already flagged).
func (d *Detector) RecordMatch(host, templateID string) bool {
	if host == "" || templateID == "" {
		return false
	}

	d.mu.Lock()
	entry, exists := d.cache.Get(host)
	if !exists {
		entry = &hostEntry{
			templates: make(map[string]struct{}),
		}
		d.cache.Add(host, entry)
	}
	d.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Always record this template match (even if already flagged)
	// This keeps GetMatchCount accurate for reporting
	entry.templates[templateID] = struct{}{}

	// Already flagged, just return true
	if entry.flagged {
		return true
	}

	// Check if we crossed the threshold
	if len(entry.templates) >= d.threshold {
		entry.flagged = true
		d.honeypotCount.Add(1)

		d.mu.RLock()
		verbose := d.verbose
		d.mu.RUnlock()

		if verbose {
			gologger.Verbose().Msgf("Honeypot detected: %s (matched %d distinct templates)", host, len(entry.templates))
		}
		return true
	}

	return false
}

// IsHoneypot checks if a host has been flagged as a honeypot.
func (d *Detector) IsHoneypot(host string) bool {
	if host == "" {
		return false
	}

	d.mu.RLock()
	entry, exists := d.cache.Get(host)
	d.mu.RUnlock()

	if !exists {
		return false
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.flagged
}

// GetMatchCount returns the number of distinct template matches for a host.
func (d *Detector) GetMatchCount(host string) int {
	if host == "" {
		return 0
	}

	d.mu.RLock()
	entry, exists := d.cache.Get(host)
	d.mu.RUnlock()

	if !exists {
		return 0
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	return len(entry.templates)
}

// GetHoneypotCount returns the total number of hosts flagged as honeypots.
func (d *Detector) GetHoneypotCount() int {
	return int(d.honeypotCount.Load())
}

// GetFlaggedHosts returns a list of all hosts that have been flagged as honeypots.
func (d *Detector) GetFlaggedHosts() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var flagged []string
	for _, host := range d.cache.Keys() {
		entry, exists := d.cache.Peek(host)
		if exists {
			entry.mu.Lock()
			if entry.flagged {
				flagged = append(flagged, host)
			}
			entry.mu.Unlock()
		}
	}
	return flagged
}

// Close cleans up resources used by the detector.
func (d *Detector) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache.Purge()
}
