package honeypot

import (
	"sync"
)

// Detector tracks unique template matches per host and flags honeypot candidates.
// It is safe for concurrent use.
type Detector struct {
	threshold int       // number of distinct template matches to flag a host
	counts    sync.Map  // map[host]*sync.Map storing templateID set
	// flagged hosts store
	flagged sync.Map // map[host]bool
}

// NewDetector creates a Detector with the given threshold. A threshold of 0 disables detection.
func NewDetector(threshold int) *Detector {
	return &Detector{threshold: threshold}
}

// RecordMatch records that templateID matched on host. It returns true if the host
// has crossed the threshold and is now flagged as a honeypot.
func (d *Detector) RecordMatch(host, templateID string) bool {
	// get or create per-host set
	setIface, _ := d.counts.LoadOrStore(host, &sync.Map{})
	tplSet := setIface.(*sync.Map)
	tplSet.LoadOrStore(templateID, struct{}{})
	// count unique templates
	count := 0
	tplSet.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if d.threshold > 0 && count >= d.threshold {
		d.flagged.Store(host, true)
		return true
	}
	return false
}

// IsFlagged returns whether the host has been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	flagged, _ := d.flagged.Load(host)
	if b, ok := flagged.(bool); ok {
		return b
	}
	return false
}