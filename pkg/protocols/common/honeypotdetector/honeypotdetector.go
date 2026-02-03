// Package honeypotdetector provides detection of honeypot hosts that match
// an unusually high number of nuclei templates, indicating fake/trap servers.
package honeypotdetector

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
)

// DefaultThreshold is the default number of distinct template matches to flag as honeypot
const DefaultThreshold = 10

// Detector tracks template match density per host to identify honeypots.
// Honeypots often serve responses that match many nuclei templates at once,
// which is a clear indicator of a fake/trap host designed to fool scanners.
type Detector struct {
	// hosts stores host entries keyed by normalized hostname
	hosts sync.Map // map[string]*hostEntry
	// threshold is the number of distinct templates that triggers honeypot detection
	threshold int
	// verbose enables verbose logging output
	verbose bool
	// verboseMu protects verbose flag
	verboseMu sync.RWMutex
	// honeypotCount tracks the total number of flagged honeypots (atomic)
	honeypotCount atomic.Int32
}

// hostEntry tracks distinct template IDs for a single host
type hostEntry struct {
	// templates stores the set of distinct template IDs that matched this host
	templates map[string]struct{}
	// flagged indicates whether this host has been marked as a honeypot
	flagged bool
	// mu protects this entry for concurrent access
	mu sync.Mutex
}

// New creates a new honeypot detector with configurable threshold.
// threshold: number of distinct template matches to trigger honeypot detection
func New(threshold int) *Detector {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Detector{
		threshold: threshold,
	}
}

// SetVerbose enables verbose logging
func (d *Detector) SetVerbose(verbose bool) {
	d.verboseMu.Lock()
	defer d.verboseMu.Unlock()
	d.verbose = verbose
}

// RecordMatch records a template match for a host and returns true if the host
// is now flagged as a honeypot (either newly flagged or already flagged).
// Host is normalized to lowercase for consistent matching with blocklists.
func (d *Detector) RecordMatch(host, templateID string) bool {
	if host == "" || templateID == "" {
		return false
	}
	// Normalize host to lowercase for consistent matching
	host = strings.ToLower(strings.TrimSpace(host))

	// Get or create entry for this host
	val, _ := d.hosts.LoadOrStore(host, &hostEntry{
		templates: make(map[string]struct{}),
	})
	entry := val.(*hostEntry)

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

		d.verboseMu.RLock()
		verbose := d.verbose
		d.verboseMu.RUnlock()

		if verbose {
			gologger.Verbose().Msgf("Honeypot detected: %s (matched %d distinct templates)", host, len(entry.templates))
		}
		return true
	}

	return false
}

// IsHoneypot checks if a host has been flagged as a honeypot.
// Host is normalized to lowercase for consistent matching with blocklists.
func (d *Detector) IsHoneypot(host string) bool {
	if host == "" {
		return false
	}
	// Normalize host to lowercase for consistent matching
	host = strings.ToLower(strings.TrimSpace(host))

	val, exists := d.hosts.Load(host)
	if !exists {
		return false
	}

	entry := val.(*hostEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.flagged
}

// GetMatchCount returns the number of distinct template matches for a host.
// Host is normalized to lowercase for consistent matching with blocklists.
func (d *Detector) GetMatchCount(host string) int {
	if host == "" {
		return 0
	}
	// Normalize host to lowercase for consistent matching
	host = strings.ToLower(strings.TrimSpace(host))

	val, exists := d.hosts.Load(host)
	if !exists {
		return 0
	}

	entry := val.(*hostEntry)
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
	var flagged []string
	d.hosts.Range(func(key, value any) bool {
		host := key.(string)
		entry := value.(*hostEntry)
		entry.mu.Lock()
		if entry.flagged {
			flagged = append(flagged, host)
		}
		entry.mu.Unlock()
		return true
	})
	return flagged
}

// Close cleans up resources used by the detector.
func (d *Detector) Close() {
	// sync.Map doesn't need explicit cleanup, but we clear it for consistency
	d.hosts.Range(func(key, _ any) bool {
		d.hosts.Delete(key)
		return true
	})
}

// LoadBlocklist loads known honeypot hosts from a file and pre-flags them.
// Each line in the file should contain one host (blank lines and # comments are ignored).
// Duplicate hosts are deduplicated. Returns the number of unique hosts loaded and any error.
func (d *Detector) LoadBlocklist(filepath string) (unique int, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	seen := make(map[string]struct{})
	var entries int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Support CSV export format: host,match_count
		// Extract only the host (first column) for round-trip compatibility
		if idx := strings.Index(line, ","); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		entries++

		// Normalize and deduplicate
		host := strings.ToLower(line)
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}

		// Pre-flag this host as a honeypot
		d.preFlagHost(host)
		unique++
	}

	if err := scanner.Err(); err != nil {
		return unique, err
	}

	if unique > 0 {
		if entries != unique {
			gologger.Info().Msgf("Loaded %d unique honeypot hosts from blocklist (%d entries, %d duplicates skipped)", unique, entries, entries-unique)
		} else {
			gologger.Info().Msgf("Loaded %d honeypot hosts from blocklist", unique)
		}
	}

	return unique, nil
}

// preFlagHost adds a host to the map and marks it as a honeypot.
// This is used for loading blocklists of known honeypots.
func (d *Detector) preFlagHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}

	// Get or create entry for this host
	val, _ := d.hosts.LoadOrStore(host, &hostEntry{
		templates: make(map[string]struct{}),
	})
	entry := val.(*hostEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if !entry.flagged {
		entry.flagged = true
		// Mark as pre-loaded blocklist entry
		entry.templates["__blocklist__"] = struct{}{}
		d.honeypotCount.Add(1)
	}
}
