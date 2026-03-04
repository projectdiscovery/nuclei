package honeypot

import (
	"fmt"
	"sync"
)

// Detector tracks unique template matches per host and flags potential honeypots.
type Detector struct {
	mu           sync.Mutex
	hosts        map[string]map[string]struct{}
	threshold    int
	warnedHosts  map[string]bool
}

// NewDetector creates a Detector with the given threshold. If threshold <= 0, detection is disabled.
func NewDetector(threshold int) *Detector {
	return &Detector{
		hosts:       make(map[string]map[string]struct{}),
		threshold:   threshold,
		warnedHosts: make(map[string]bool),
	}
}

// Record registers a match of templateID on host. If the number of unique templates
// exceeds the threshold, a one-time warning is emitted.
func (d *Detector) Record(host, templateID string) {
	if d.threshold <= 0 {
		return // detection disabled
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	set, ok := d.hosts[host]
	if !ok {
		set = make(map[string]struct{})
		d.hosts[host] = set
	}
	// already recorded this template for this host
	if _, exists := set[templateID]; exists {
		return
	}
	set[templateID] = struct{}{}

	if len(set) > d.threshold && !d.warnedHosts[host] {
		fmt.Printf("[Honeypot Detection] host %s flagged as potential honeypot: %d unique templates matched (threshold %d)\n", host, len(set), d.threshold)
		d.warnedHosts[host] = true
	}
}

// IsFlagged returns true if the host has already been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.warnedHosts[host]
}
