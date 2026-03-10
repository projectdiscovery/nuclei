package honeypot

import (
	"fmt"
	"sync"
)

// Detector tracks template matches per host to identify potential honeypots
type Detector struct {
	// hostMatches tracks unique template matches per host
	hostMatches sync.Map // map[string]map[string]struct{}
	
	// threshold is the number of unique template matches that triggers honeypot detection
	threshold int
	
	// flaggedHosts tracks hosts already flagged as honeypots
	flaggedHosts sync.Map // map[string]bool
	
	// mu protects threshold updates
	mu sync.RWMutex
	
	// onHoneypotDetected is called when a host is flagged as a honeypot
	onHoneypotDetected func(host string, matchCount int)
}

// Config holds configuration for the honeypot detector
type Config struct {
	Threshold          int
	OnHoneypotDetected func(host string, matchCount int)
}

// New creates a new honeypot detector with the given configuration
func New(cfg Config) *Detector {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 20 // default threshold
	}
	
	return &Detector{
		threshold:          cfg.Threshold,
		onHoneypotDetected: cfg.OnHoneypotDetected,
	}
}

// RecordMatch records a template match for a host
// Returns true if this match triggered honeypot detection
func (d *Detector) RecordMatch(host, templateID string) bool {
	if host == "" || templateID == "" {
		return false
	}
	
	// Get or create the match set for this host
	matchesInterface, _ := d.hostMatches.LoadOrStore(host, &sync.Map{})
	matches := matchesInterface.(*sync.Map)
	
	// Add the template to the set
	matches.Store(templateID, struct{}{})
	
	// Count unique matches
	matchCount := d.countMatches(matches)
	
	// Check if threshold exceeded
	d.mu.RLock()
	threshold := d.threshold
	d.mu.RUnlock()
	
	if matchCount >= threshold {
		// Check if already flagged
		if _, alreadyFlagged := d.flaggedHosts.LoadOrStore(host, true); !alreadyFlagged {
			// Newly flagged - trigger callback
			if d.onHoneypotDetected != nil {
				d.onHoneypotDetected(host, matchCount)
			}
			return true
		}
	}
	
	return false
}

// IsHoneypot checks if a host has been flagged as a honeypot
func (d *Detector) IsHoneypot(host string) bool {
	_, flagged := d.flaggedHosts.Load(host)
	return flagged
}

// GetMatchCount returns the number of unique template matches for a host
func (d *Detector) GetMatchCount(host string) int {
	matchesInterface, exists := d.hostMatches.Load(host)
	if !exists {
		return 0
	}
	
	matches := matchesInterface.(*sync.Map)
	return d.countMatches(matches)
}

// GetScore returns a honeypot score (0-100) for a host
// Score is based on the number of matches relative to the threshold
func (d *Detector) GetScore(host string) int {
	matchCount := d.GetMatchCount(host)
	
	d.mu.RLock()
	threshold := d.threshold
	d.mu.RUnlock()
	
	if matchCount == 0 {
		return 0
	}
	
	// Calculate score: (matches / threshold) * 100, capped at 100
	score := (matchCount * 100) / threshold
	if score > 100 {
		score = 100
	}
	
	return score
}

// SetThreshold updates the detection threshold
func (d *Detector) SetThreshold(threshold int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if threshold > 0 {
		d.threshold = threshold
	}
}

// GetThreshold returns the current detection threshold
func (d *Detector) GetThreshold() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.threshold
}

// Reset clears all tracked data
func (d *Detector) Reset() {
	d.hostMatches = sync.Map{}
	d.flaggedHosts = sync.Map{}
}

// GetStats returns statistics about tracked hosts
func (d *Detector) GetStats() Stats {
	stats := Stats{
		Hosts: make(map[string]int),
	}
	
	d.hostMatches.Range(func(key, value interface{}) bool {
		host := key.(string)
		matches := value.(*sync.Map)
		count := d.countMatches(matches)
		stats.Hosts[host] = count
		stats.TotalHosts++
		return true
	})
	
	d.flaggedHosts.Range(func(key, value interface{}) bool {
		stats.FlaggedHosts++
		return true
	})
	
	return stats
}

// Stats holds statistics about the detector
type Stats struct {
	TotalHosts   int
	FlaggedHosts int
	Hosts        map[string]int // host -> match count
}

// String returns a human-readable representation of the stats
func (s Stats) String() string {
	return fmt.Sprintf("Total hosts: %d, Flagged as honeypots: %d", s.TotalHosts, s.FlaggedHosts)
}

// countMatches counts the number of entries in a sync.Map
func (d *Detector) countMatches(m *sync.Map) int {
	count := 0
	m.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}
