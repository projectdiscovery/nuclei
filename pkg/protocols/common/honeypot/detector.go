package honeypot

import (
	"sync"
)

// HoneypotDetector tracks potential honeypot indicators
type HoneypotDetector struct {
	hostVulnCount map[string]int
	hostPatterns  map[string]map[string]struct{} // FIX: Use map instead of slice to prevent duplicates
	mu            sync.RWMutex
	threshold     int // Default: 10 vulnerabilities per host
}

// NewHoneypotDetector creates a new honeypot detector
func NewHoneypotDetector(threshold int) *HoneypotDetector {
	if threshold <= 0 {
		threshold = 10 // Default threshold
	}
	return &HoneypotDetector{
		hostVulnCount: make(map[string]int),
		hostPatterns:  make(map[string]map[string]struct{}), // FIX: Initialize as map of maps
		threshold:     threshold,
	}
}

// AddVulnerability records a vulnerability match for a host
// FIX: Only increment count if template ID is new for this host
func (h *HoneypotDetector) AddVulnerability(host string, templateID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Initialize pattern set for host if needed
	if h.hostPatterns[host] == nil {
		h.hostPatterns[host] = make(map[string]struct{})
	}

	// Only increment count if this is a new template ID (prevent duplicates)
	if _, exists := h.hostPatterns[host][templateID]; !exists {
		h.hostPatterns[host][templateID] = struct{}{}
		h.hostVulnCount[host]++
	}
}

// IsHoneypot checks if a host exhibits honeypot characteristics
func (h *HoneypotDetector) IsHoneypot(host string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	count, exists := h.hostVulnCount[host]
	return exists && count >= h.threshold
}

// GetVulnerabilityCount returns the number of vulnerabilities found on a host
func (h *HoneypotDetector) GetVulnerabilityCount(host string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	count, exists := h.hostVulnCount[host]
	if !exists {
		return 0
	}
	return count
}

// GetHoneypotScore calculates a honeypot probability score (0-100)
func (h *HoneypotDetector) GetHoneypotScore(host string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	count, exists := h.hostVulnCount[host]
	if !exists || count == 0 {
		return 0
	}

	// Score calculation:
	// 0-10 vulns: 0-50 score (linear)
	// 10-20 vulns: 50-80 score
	// 20+ vulns: 80-100 score
	if count <= 10 {
		return count * 5
	} else if count <= 20 {
		return 50 + (count-10)*3
	}
	return 80 + min((count-20)*2, 20)
}

// GetPatterns returns all template IDs matched for a host
func (h *HoneypotDetector) GetPatterns(host string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	patterns, exists := h.hostPatterns[host]
	if !exists {
		return []string{}
	}

	// Convert map keys to slice
	result := make([]string, 0, len(patterns))
	for pattern := range patterns {
		result = append(result, pattern)
	}
	return result
}

// Reset clears all tracked data for a host
func (h *HoneypotDetector) Reset(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.hostVulnCount, host)
	delete(h.hostPatterns, host)
}

// ResetAll clears all tracked data
func (h *HoneypotDetector) ResetAll() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.hostVulnCount = make(map[string]int)
	h.hostPatterns = make(map[string]map[string]struct{}) // FIX: Initialize as map of maps
}

// GetStats returns detector statistics
func (h *HoneypotDetector) GetStats() HoneypotStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	totalHosts := len(h.hostVulnCount)
	honeypotHosts := 0
	maxVulns := 0

	for _, count := range h.hostVulnCount {
		if count >= h.threshold {
			honeypotHosts++
		}
		if count > maxVulns {
			maxVulns = count
		}
	}

	return HoneypotStats{
		TotalHosts:     totalHosts,
		HoneypotHosts:  honeypotHosts,
		MaxVulnsOnHost: maxVulns,
		Threshold:      h.threshold,
	}
}

// HoneypotStats contains detector statistics
type HoneypotStats struct {
	TotalHosts     int
	HoneypotHosts  int
	MaxVulnsOnHost int
	Threshold      int
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
