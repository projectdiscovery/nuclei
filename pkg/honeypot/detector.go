package honeypot

import (
	"crypto/md5"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// DetectionMode specifies how honeypots should be handled when detected.
type DetectionMode string

const (
	// ModeWarn emits a warning but includes the results (default)
	ModeWarn DetectionMode = "warn"
	// ModeTag adds a metadata tag to flagged results
	ModeTag DetectionMode = "tag"
	// ModeSuppress filters out flagged results
	ModeSuppress DetectionMode = "suppress"
)

// Config holds configuration for honeypot detection
type Config struct {
	// Enabled determines if honeypot detection is active
	Enabled bool
	// Mode specifies the action to take when a honeypot is detected
	Mode DetectionMode
	// Logger is called with warning messages
	Logger func(string)
}

// hostMetrics tracks match statistics per host
type hostMetrics struct {
	templates      map[string]*templateInfo // templateID -> info
	responseHashes map[string]int           // response hash -> count
	categories     map[string]bool          // distinct categories seen
	tags           map[string]bool          // distinct tags seen
	matchCount     int
	totalResponses int
	lock           sync.RWMutex
}

type templateInfo struct {
	templateID string
	categories []string
	tags       []string
	response   string
}

// Detector analyzes match patterns to identify suspicious honeypot behavior.
// It is designed to be conservative to minimize false positives, using multiple
// signals (match count, category diversity, response similarity, tech stack conflicts).
type Detector struct {
	config Config
	// hostData maps host -> metrics
	hostData map[string]*hostMetrics
	lock     sync.RWMutex

	// conflictTechs is a hardcoded list of tech pairs that should not appear together
	// on a real system (e.g., Cisco + Fortinet security)
	conflictTechs map[string]map[string]bool
}

// New creates a new Detector with the provided configuration.
func New(config Config) *Detector {
	if config.Logger == nil {
		config.Logger = func(string) {}
	}

	return &Detector{
		config:   config,
		hostData: make(map[string]*hostMetrics),
		conflictTechs: map[string]map[string]bool{
			"cisco": {
				"fortinet":         true,
				"paloaltonetworks": true,
				"juniper":          true,
			},
			"fortinet": {
				"cisco":            true,
				"paloaltonetworks": true,
				"juniper":          true,
			},
			"paloaltonetworks": {
				"cisco":    true,
				"fortinet": true,
				"juniper":  true,
			},
			"juniper": {
				"cisco":            true,
				"fortinet":         true,
				"paloaltonetworks": true,
			},
			"apache": {
				"iis":   true,
				"nginx": true,
			},
			"iis": {
				"apache": true,
				"nginx":  true,
			},
			"nginx": {
				"apache": true,
				"iis":    true,
			},
		},
	}
}

// recordMatch records a template match for a host. This should be called
// whenever a template successfully matches a target.
func (d *Detector) recordMatch(host string, event *output.ResultEvent) {
	if !d.config.Enabled || event == nil {
		return
	}

	host = normalizeHost(host)
	if host == "" {
		return
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	if _, exists := d.hostData[host]; !exists {
		d.hostData[host] = &hostMetrics{
			templates:      make(map[string]*templateInfo),
			responseHashes: make(map[string]int),
			categories:     make(map[string]bool),
			tags:           make(map[string]bool),
		}
	}

	metrics := d.hostData[host]
	metrics.lock.Lock()
	defer metrics.lock.Unlock()

	// Record template match
	tplID := event.TemplateID

	var tags []string
	tags = event.Info.Tags.ToSlice()

	if _, exists := metrics.templates[tplID]; !exists {
		metrics.templates[tplID] = &templateInfo{
			templateID: tplID,
			categories: tags,
			tags:       tags,
			response:   event.Response,
		}
		// Only increment matchCount for unique template IDs
		metrics.matchCount++
	}

	// Record response hash for similarity detection
	if event.Response != "" {
		hash := hashResponse(event.Response)
		metrics.responseHashes[hash]++
		metrics.totalResponses++
	}

	// Record tags as category proxies (more granular than Info.Classification)
	for _, tag := range event.Info.Tags.ToSlice() {
		metrics.categories[tag] = true
	}
}

// hashResponse creates a simple hash of the response for similarity detection
func hashResponse(resp string) string {
	h := md5.Sum([]byte(resp))
	return fmt.Sprintf("%x", h)
}

// normalizeHost removes scheme and port for consistent host identification
func normalizeHost(host string) string {
	// In a real implementation, we'd use urlutil here, but for clarity:
	// Just return the host as-is for now; actual implementation could parse URL
	return host
}

// IsHoneypot analyzes the collected metrics for a host and returns whether
// it matches the honeypot pattern. It uses multi-signal detection:
//
// 1. High match count (>=20 templates)
// 2. High tag/category diversity (>=6 distinct categories)
// 3. High response reuse (>=80% of responses are identical)
// 4. Conflicting tech stack indicators
//
// A honeypot is flagged when at least 3 out of 4 signals are detected.
func (d *Detector) IsHoneypot(host string) (bool, *HoneypotReport) {
	host = normalizeHost(host)
	if host == "" {
		return false, nil
	}

	d.lock.RLock()
	metrics, exists := d.hostData[host]
	d.lock.RUnlock()

	if !exists || metrics == nil {
		return false, nil
	}

	metrics.lock.RLock()
	defer metrics.lock.RUnlock()

	report := &HoneypotReport{
		Host:    host,
		Signals: []string{},
		Score:   0,
	}

	// Signal 1: High match count
	hasHighMatchCount := metrics.matchCount >= 20
	if hasHighMatchCount {
		report.Signals = append(report.Signals, fmt.Sprintf("%d templates matched", metrics.matchCount))
		report.Score++
	}

	// Signal 2: High category/tag diversity
	categoryCount := len(metrics.categories)
	hasHighDiversity := categoryCount >= 6
	if hasHighDiversity {
		report.Signals = append(report.Signals, fmt.Sprintf("%d unrelated categories", categoryCount))
		report.Score++
	}

	// Signal 3: High response body reuse
	if metrics.totalResponses > 0 {
		// Find the most common response hash
		maxCount := 0
		for _, count := range metrics.responseHashes {
			if count > maxCount {
				maxCount = count
			}
		}
		reuseRatio := float64(maxCount) / float64(metrics.totalResponses)
		if reuseRatio >= 0.8 {
			report.Signals = append(report.Signals, fmt.Sprintf("%.0f%% identical response bodies", reuseRatio*100))
			report.Score++
		}
	}

	// Signal 4: Conflicting tech stack
	hasConflict := d.hasConflictingTechs(metrics)
	if hasConflict {
		report.Signals = append(report.Signals, "conflicting technology stack detected")
		report.Score++
	}

	// Conservative detection: require at least 3 signals
	// This prevents false positives from legitimate services with many templates
	isHoneypot := report.Score >= 3

	return isHoneypot, report
}

// hasConflictingTechs checks if the matched templates suggest incompatible technologies
func (d *Detector) hasConflictingTechs(metrics *hostMetrics) bool {
	seenTechs := make(map[string]bool)

	for _, info := range metrics.templates {
		// Extract tech from categories/tags (simplified: just use lowercase tag names)
		for _, tag := range info.tags {
			normalizedTag := strings.ToLower(tag)
			if conflicts, found := d.conflictTechs[normalizedTag]; found {
				for seenTech := range seenTechs {
					if conflicts[seenTech] {
						return true
					}
				}
				seenTechs[normalizedTag] = true
			}
		}
	}
	return false
}

// GetReport returns the honeypot analysis for a host without modifying state
func (d *Detector) GetReport(host string) *HoneypotReport {
	isHoneypot, report := d.IsHoneypot(host)
	if !isHoneypot {
		return nil
	}
	return report
}

// HoneypotReport contains the analysis result for a potentially honeypotted host
type HoneypotReport struct {
	Host    string   // The analyzed host
	Signals []string // Reasons why this host was flagged
	Score   int      // Number of signals detected (0-4)
}

// String returns a formatted warning message for the report
func (r *HoneypotReport) String() string {
	msg := "\n[HONEYPOT WARNING]\n"
	msg += fmt.Sprintf("Host: %s\n", r.Host)
	msg += "Reason:\n"
	for _, signal := range r.Signals {
		msg += fmt.Sprintf("  - %s\n", signal)
	}
	msg += "Results may be unreliable.\n"
	return msg
}
