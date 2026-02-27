package honeypot

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// hostState tracks per-host match metadata for confidence scoring and reporting.
type hostState struct {
	// templates is the set of unique template IDs matched.
	templates map[string]struct{}
	// firstSeen is the timestamp of the first match recorded for this host.
	firstSeen time.Time
	// sampleTemplates stores up to maxSampleTemplates IDs for reporting.
	sampleTemplates []string
}

const maxSampleTemplates = 10

// Detector tracks unique template matches per host to identify potential honeypots.
// Honeypots are hosts that respond positively to an unusually high number of vulnerability
// checks, indicating they are deliberately mirroring scanner signatures to produce false positives.
type Detector struct {
	// threshold is the minimum number of unique template matches to flag a host as a honeypot.
	// A value of 0 means detection is disabled.
	threshold int
	// suppress controls whether results from flagged hosts are suppressed (true) or only warned (false).
	suppress bool
	// hosts tracks per-host match state. Once flagged, the entry is moved to flaggedState
	// and removed from hosts to bound memory.
	hosts map[string]*hostState
	// flaggedState stores metadata for flagged hosts, used for scoring and reporting.
	flaggedState map[string]*flaggedHost
	// totalHosts tracks the number of distinct hosts seen (for report summary).
	totalHosts map[string]struct{}
	// suppressedCount tracks the number of results suppressed due to honeypot flagging.
	suppressedCount int
	// mu protects concurrent access to all maps.
	mu sync.RWMutex
}

// flaggedHost stores metadata about a host that has been flagged as a honeypot.
type flaggedHost struct {
	matchCount      int
	score           float64
	firstSeen       time.Time
	flaggedAt       time.Time
	sampleTemplates []string
}

// New creates a new honeypot Detector with the given threshold and suppression mode.
// A threshold of 0 disables detection entirely.
func New(threshold int, suppress bool) *Detector {
	return &Detector{
		threshold:    threshold,
		suppress:     suppress,
		hosts:        make(map[string]*hostState),
		flaggedState: make(map[string]*flaggedHost),
		totalHosts:   make(map[string]struct{}),
	}
}

// Enabled returns true if honeypot detection is active.
func (d *Detector) Enabled() bool {
	return d != nil && d.threshold > 0
}

// Record registers a template match for a host and returns whether the result
// should be suppressed. It returns (isFlagged, shouldSuppress).
//
// isFlagged is true if the host has been identified as a potential honeypot.
// shouldSuppress is true only if isFlagged is true AND suppress mode is enabled.
func (d *Detector) Record(host, templateID string) (isFlagged, shouldSuppress bool) {
	if !d.Enabled() {
		return false, false
	}
	if host == "" || templateID == "" {
		return false, false
	}

	normalizedHost := normalizeHost(host)
	if normalizedHost == "" {
		return false, false
	}

	d.mu.Lock()

	// Track total unique hosts for reporting
	d.totalHosts[normalizedHost] = struct{}{}

	// If already flagged, skip counting
	if _, ok := d.flaggedState[normalizedHost]; ok {
		if d.suppress {
			d.suppressedCount++
		}
		d.mu.Unlock()
		return true, d.suppress
	}

	hs, ok := d.hosts[normalizedHost]
	if !ok {
		hs = &hostState{
			templates: make(map[string]struct{}),
			firstSeen: time.Now(),
		}
		d.hosts[normalizedHost] = hs
	}

	// Check if this is a new template before adding to the set
	_, alreadySeen := hs.templates[templateID]
	hs.templates[templateID] = struct{}{}

	// Track sample templates for reporting (up to maxSampleTemplates).
	// Dedup is guaranteed by the alreadySeen check above — no linear scan needed.
	if !alreadySeen && len(hs.sampleTemplates) < maxSampleTemplates {
		hs.sampleTemplates = append(hs.sampleTemplates, templateID)
	}

	// Cap check: once the per-host set reaches threshold, flag and prune.
	// This bounds each host's set to at most threshold entries; combined
	// with pruning on flag, total memory is O(uniqueHosts × threshold).
	if len(hs.templates) >= d.threshold {
		matchCount := len(hs.templates)
		score := d.computeScore(matchCount)
		d.flaggedState[normalizedHost] = &flaggedHost{
			matchCount:      matchCount,
			score:           score,
			firstSeen:       hs.firstSeen,
			flaggedAt:       time.Now(),
			sampleTemplates: hs.sampleTemplates,
		}
		delete(d.hosts, normalizedHost)
		if d.suppress {
			d.suppressedCount++
		}
		d.mu.Unlock()
		gologger.Warning().Msgf("[honeypot] %s matched %d unique templates (threshold: %d, score: %.2f) — likely honeypot", normalizedHost, matchCount, d.threshold, score)
		return true, d.suppress
	}

	d.mu.Unlock()
	return false, false
}

// computeScore calculates a confidence score (0.0-1.0) based on how far the match
// count exceeds the threshold. At exactly the threshold the score is 0.5; it
// approaches 1.0 asymptotically as matches increase. Must be called under lock.
func (d *Detector) computeScore(matchCount int) float64 {
	// Ratio of matches to a saturation point of 2× threshold.
	// At threshold: 0.5, at 2× threshold: ~0.8, capped at 1.0.
	ratio := float64(matchCount) / float64(d.threshold*2)
	return math.Min(ratio, 1.0)
}

// Score returns the honeypot confidence score for a host (0.0-1.0).
// Returns 0.0 for hosts that are not flagged.
func (d *Detector) Score(host string) float64 {
	if !d.Enabled() {
		return 0.0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if fh, ok := d.flaggedState[normalizeHost(host)]; ok {
		return fh.score
	}
	return 0.0
}

// IsFlagged returns whether a host has been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	if !d.Enabled() {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.flaggedState[normalizeHost(host)]
	return ok
}

// FlaggedHosts returns a list of all hosts flagged as honeypots with their match counts.
func (d *Detector) FlaggedHosts() map[string]int {
	if !d.Enabled() {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]int, len(d.flaggedState))
	for host, fh := range d.flaggedState {
		result[host] = fh.matchCount
	}
	return result
}

// Summary returns a human-readable summary of flagged hosts, or an empty string if none.
func (d *Detector) Summary() string {
	if !d.Enabled() {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.flaggedState) == 0 {
		return ""
	}

	// Sort hosts for deterministic output across runs
	hosts := make([]string, 0, len(d.flaggedState))
	for host := range d.flaggedState {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[honeypot] %d host(s) flagged as potential honeypot(s):\n", len(d.flaggedState)))
	for _, host := range hosts {
		fh := d.flaggedState[host]
		sb.WriteString(fmt.Sprintf("  - %s (%d unique template matches, score: %.2f)\n", host, fh.matchCount, fh.score))
	}
	return sb.String()
}

// ReportEntry represents a single flagged host in the honeypot JSON report.
type ReportEntry struct {
	Host                   string   `json:"host"`
	Score                  float64  `json:"score"`
	UniqueTemplatesMatched int      `json:"unique_templates_matched"`
	FirstSeen              string   `json:"first_seen"`
	FlaggedAt              string   `json:"flagged_at"`
	SampleTemplates        []string `json:"sample_templates"`
}

// ReportSummary contains aggregate scan statistics for the honeypot report.
type ReportSummary struct {
	TotalHosts        int `json:"total_hosts"`
	FlaggedHosts      int `json:"flagged_hosts"`
	SuppressedResults int `json:"suppressed_results"`
}

// Report is the top-level JSON structure for the honeypot report output.
type Report struct {
	FlaggedHosts []ReportEntry `json:"flagged_hosts"`
	ScanSummary  ReportSummary `json:"scan_summary"`
}

// WriteReport writes a JSON honeypot report to the specified file path.
// Returns nil if detection is disabled or no hosts were flagged.
func (d *Detector) WriteReport(filePath string) error {
	if !d.Enabled() || filePath == "" {
		return nil
	}

	d.mu.RLock()
	report := d.buildReport()
	d.mu.RUnlock()

	if len(report.FlaggedHosts) == 0 {
		return nil
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal honeypot report: %w", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create honeypot report file %s: %w", filePath, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write honeypot report to %s: %w", filePath, err)
	}

	gologger.Info().Msgf("[honeypot] report written to %s", filePath)
	return nil
}

// buildReport constructs the report structure. Must be called under at least RLock.
func (d *Detector) buildReport() Report {
	entries := make([]ReportEntry, 0, len(d.flaggedState))
	for host, fh := range d.flaggedState {
		entries = append(entries, ReportEntry{
			Host:                   host,
			Score:                  fh.score,
			UniqueTemplatesMatched: fh.matchCount,
			FirstSeen:              fh.firstSeen.UTC().Format(time.RFC3339),
			FlaggedAt:              fh.flaggedAt.UTC().Format(time.RFC3339),
			SampleTemplates:        fh.sampleTemplates,
		})
	}
	// Sort by score descending, then by host ascending for deterministic output
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Score != entries[j].Score {
			return entries[i].Score > entries[j].Score
		}
		return entries[i].Host < entries[j].Host
	})

	return Report{
		FlaggedHosts: entries,
		ScanSummary: ReportSummary{
			TotalHosts:        len(d.totalHosts),
			FlaggedHosts:      len(d.flaggedState),
			SuppressedResults: d.suppressedCount,
		},
	}
}

// normalizeHost extracts a consistent host identifier from various URL/host formats.
// It strips scheme, path, query, fragment, and userinfo, keeping only host:port.
func normalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// If it looks like a URL, parse it
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil {
			host := u.Hostname()
			if host == "" {
				return ""
			}
			port := u.Port()
			isIPv6 := strings.Contains(host, ":")
			if port != "" {
				// Preserve bracket notation for IPv6 to avoid ambiguity
				if isIPv6 {
					return "[" + host + "]:" + port
				}
				return host + ":" + port
			}
			// Wrap bare IPv6 in brackets for consistency with non-URL input "[::1]"
			if isIPv6 {
				return "[" + host + "]"
			}
			return host
		}
	}

	// Strip any path component
	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}

	// Strip userinfo if present (user:pass@host)
	if idx := strings.LastIndex(input, "@"); idx != -1 {
		input = input[idx+1:]
	}

	// Preserve IPv6 bracket notation: [::1]:8080 stays as [::1]:8080
	if strings.HasPrefix(input, "[") {
		if closeBracket := strings.Index(input, "]"); closeBracket != -1 {
			host := input[1:closeBracket]
			if closeBracket+1 < len(input) && input[closeBracket+1] == ':' {
				return "[" + host + "]:" + input[closeBracket+2:]
			}
			return "[" + host + "]"
		}
	}

	// Detect bare IPv6 without brackets (e.g., "::1", "fe80::1").
	// Two or more colons distinguishes IPv6 from host:port (which has exactly one).
	// Wrap in brackets for consistency with all other IPv6 code paths above.
	if strings.Count(input, ":") >= 2 {
		return "[" + input + "]"
	}

	// Reject degenerate inputs that reduce to punctuation-only after stripping
	// (e.g., "://" → ":" after path/userinfo stripping).
	if strings.Trim(input, ":/") == "" {
		return ""
	}

	// Strip trailing colon (host with no port, e.g., "host:").
	// "host" and "host:" refer to the same target; treat them identically
	// to avoid splitting match counts for the same actual host.
	input = strings.TrimRight(input, ":")

	return input
}
