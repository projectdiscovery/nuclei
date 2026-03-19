package honeypot

import (
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Detector manages honeypot detection per host
type Detector struct {
	mu              sync.RWMutex
	matchCount      map[string]int       // host -> unique template match count
	hostTimestamps  map[string]time.Time // host -> first match time
	threshold       int
	enabled         bool
	resetInterval   time.Duration // optional periodic reset
	lastReset       time.Time
}

// New creates a new honeypot detector
func New(options *types.Options) *Detector {
	if !options.HoneypotDetectionEnabled {
		return &Detector{enabled: false}
	}
	threshold := options.HoneypotMatchThreshold
	if threshold <= 0 {
		threshold = 50 // sensible default
	}
	resetInterval := time.Duration(options.HoneypotResetIntervalSeconds) * time.Second
	if resetInterval <= 0 {
		resetInterval = 0 // disabled by default
	}
	return &Detector{
		matchCount:     make(map[string]int),
		hostTimestamps: make(map[string]time.Time),
		threshold:      threshold,
		enabled:        true,
		resetInterval:  resetInterval,
		lastReset:      time.Now(),
	}
}

// RecordMatch records a template match for a host
// Returns true if this host should now be considered a honeypot
func (d *Detector) RecordMatch(host, templateID string) bool {
	if !d.enabled || host == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Periodic reset to avoid stale counts
	if d.resetInterval > 0 && time.Since(d.lastReset) > d.resetInterval {
		d.matchCount = make(map[string]int)
		d.lastReset = time.Now()
	}

	// Record first timestamp if new host
	if _, ok := d.hostTimestamps[host]; !ok {
		d.hostTimestamps[host] = time.Now()
	}

	// Increment unique template match count
	d.matchCount[host]++

	return d.matchCount[host] >= d.threshold
}

// IsHoneypot checks if a host is marked as honeypot
func (d *Detector) IsHoneypot(host string) bool {
	if !d.enabled || host == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.matchCount[host] >= d.threshold
}

// GetMatchCount returns match count for a host
func (d *Detector) GetMatchCount(host string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.matchCount[host]
}

// ResetForHost resets match count for a host
func (d *Detector) ResetForHost(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.matchCount, host)
	delete(d.hostTimestamps, host)
}
