package honeypot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// Detector identifies potential honeypot responses that fake vulnerability findings.
// Honeypots are servers that respond with the same vulnerability indicators 
// for many different vulnerability templates, creating false positives.
type Detector struct {
	mu sync.RWMutex
	
	// Tracks matches per host+response hash
	hostMatches map[string]*hostMatchInfo
	
	// Configuration
	threshold int // minimum matches to flag as honeypot
}

// hostMatchInfo tracks match information for a specific host+response combination
type hostMatchInfo struct {
	templateIDs map[string]struct{} // unique template IDs that matched this response
	matchCount  int
	response    string              // truncated response for debugging
}

// Result contains the honeypot detection result
type Result struct {
	IsHoneypot       bool     // true if this appears to be a honeypot
	Confidence       float64  // 0.0 to 1.0 confidence score
	MatchedTemplates []string // list of template IDs that matched
	Reason           string   // human-readable reason
}

// New creates a new honeypot detector with default settings
func New() *Detector {
	return &Detector{
		hostMatches:    make(map[string]*hostMatchInfo),
		threshold:      5, // flag as honeypot if 5+ templates match same response
	}
}

// NewWithOptions creates a new detector with custom options
func NewWithOptions(threshold int) *Detector {
	d := New()
	d.threshold = threshold
	return d
}

// hashResponse creates a hash of the response content for grouping similar responses
func hashResponse(response string) string {
	// Use first 1KB of response for hashing (honeypots usually repeat the same content)
	content := response
	if len(content) > 1024 {
		content = content[:1024]
	}
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// getHostKey creates a unique key for host+response combination
func getHostKey(host, response string) string {
	responseHash := hashResponse(response)
	return fmt.Sprintf("%s|%s", host, responseHash)
}

// ProcessResult checks a result for honeypot characteristics
// Takes simple parameters instead of ResultEvent to avoid import cycle
func (d *Detector) ProcessResult(host, templateID, response string) *Result {
	if host == "" || response == "" {
		return nil
	}

	hostKey := getHostKey(host, response)
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Get or create host match info
	info, exists := d.hostMatches[hostKey]
	if !exists {
		info = &hostMatchInfo{
			templateIDs: make(map[string]struct{}),
			response:    truncateForDebug(response, 200),
		}
		d.hostMatches[hostKey] = info
	}
	
	// Add this template to the set
	info.templateIDs[templateID] = struct{}{}
	info.matchCount++
	
	// Check if this looks like a honeypot
	templateCount := len(info.templateIDs)
	if templateCount >= d.threshold {
		templates := make([]string, 0, len(info.templateIDs))
		for id := range info.templateIDs {
			templates = append(templates, id)
		}
		
		// Calculate confidence based on how many templates matched
		confidence := float64(templateCount-d.threshold+1) / float64(templateCount+1)
		if confidence > 1.0 {
			confidence = 1.0
		}
		
		return &Result{
			IsHoneypot:       true,
			Confidence:       confidence,
			MatchedTemplates: templates,
			Reason:           fmt.Sprintf("High match density: %d different templates matched the same response (threshold: %d)", templateCount, d.threshold),
		}
	}
	
	return nil
}

// truncateForDebug truncates a string for debugging purposes
func truncateForDebug(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// GetStats returns current detection statistics
func (d *Detector) GetStats() map[string]int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	stats := make(map[string]int)
	stats["total_hosts_tracked"] = len(d.hostMatches)
	
	honeypotCount := 0
	totalMatches := 0
	for _, info := range d.hostMatches {
		if len(info.templateIDs) >= d.threshold {
			honeypotCount++
		}
		totalMatches += info.matchCount
	}
	stats["potential_honeypots"] = honeypotCount
	stats["total_matches"] = totalMatches
	
	return stats
}

// Reset clears all tracked data
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hostMatches = make(map[string]*hostMatchInfo)
}

// FilterTemplateID checks if a template ID should be excluded from honeypot detection
// (some templates are expected to match everywhere, like certain fingerprint templates)
func (d *Detector) FilterTemplateID(templateID string) bool {
	// Exclude common templates that are expected to match everywhere
	excludedPrefixes := []string{
		"fingerprint/",
		"tech-detect",
		"server-status",
	}
	
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(templateID, prefix) {
			return true
		}
	}
	return false
}
