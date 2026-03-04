package honeypot

import (
	"sync"
)

// Detector tracks unique template matches per host and flags hosts exceeding a threshold.
// A nil Detector (threshold<=0) disables honeypot detection with zero overhead.
type Detector struct {
	mu        sync.RWMutex
	threshold int
	counts    map[string]map[string]struct{}
}

// New creates a Detector with the given threshold. 0 or negative disables detection (returns nil).
func New(threshold int) *Detector {
	if threshold <= 0 {
		return nil
	}
	return &Detector{
		threshold: threshold,
		counts:    make(map[string]map[string]struct{}),
	}
}

// Record logs a match of templateID on host.  It returns true if the host is now flagged as a honeypot.
func (d *Detector) Record(host, templateID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.counts[host] == nil {
		d.counts[host] = make(map[string]struct{})
	}
	d.counts[host][templateID] = struct{}{}
	return len(d.counts[host]) > d.threshold
}

// IsFlagged returns whether the host has been flagged already (len(matches) > threshold).
func (d *Detector) IsFlagged(host string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.counts[host]) > d.threshold
}

// Summary returns a snapshot of counts per host for reporting purposes.
func (d *Detector) Summary() map[string]int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	summary := make(map[string]int, len(d.counts))
	for host, tm := range d.counts {
		summary[host] = len(tm)
	}
	return summary
}