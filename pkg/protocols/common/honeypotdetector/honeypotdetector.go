package honeypotdetector

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/projectdiscovery/gologger"
)

// DefaultMaxHosts is the default maximum number of hosts to track
const DefaultMaxHosts = 10000

// DefaultThreshold is the default number of distinct template matches to flag as honeypot
const DefaultThreshold = 10

// Detector tracks template match density per host to identify honeypots.
// Honeypots often serve responses that match many nuclei templates at once,
// which is a clear indicator of a fake/trap host designed to fool scanners.
type Detector struct {
	// cache stores host entries with LRU eviction policy
	cache *lru.Cache[string, *hostEntry]
	// threshold is the number of distinct templates that triggers honeypot detection
	threshold int
	// verbose enables verbose logging output
	verbose bool
	// mu protects cache access for concurrent operations
	mu sync.RWMutex

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

// New creates a new honeypot detector with configurable threshold and max hosts.
// threshold: number of distinct template matches to trigger honeypot detection
// maxHosts: maximum number of hosts to track (uses LRU eviction)
func New(threshold, maxHosts int) *Detector {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}

	// Create detector first so the eviction callback can reference it
	detector := &Detector{
		threshold: threshold,
	}

	// Use NewWithEvict to properly decrement honeypotCount when flagged hosts are evicted
	onEvict := func(_ string, entry *hostEntry) {
		if entry != nil && entry.flagged {
			detector.honeypotCount.Add(-1)
		}
	}

	cache, err := lru.NewWithEvict[string, *hostEntry](maxHosts, onEvict)
	if err != nil {
		// This should never happen with validated maxHosts > 0, but handle gracefully
		cache, _ = lru.NewWithEvict[string, *hostEntry](DefaultMaxHosts, onEvict)
	}

	detector.cache = cache
	return detector
}

// SetVerbose enables verbose logging
func (d *Detector) SetVerbose(verbose bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.verbose = verbose
}

// RecordMatch records a template match for a host and returns true if the host
// is now flagged as a honeypot (either newly flagged or already flagged).
func (d *Detector) RecordMatch(host, templateID string) bool {
	if host == "" || templateID == "" {
		return false
	}

	d.mu.Lock()
	entry, exists := d.cache.Get(host)
	if !exists {
		entry = &hostEntry{
			templates: make(map[string]struct{}),
		}
		d.cache.Add(host, entry)
	}
	d.mu.Unlock()

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

		d.mu.RLock()
		verbose := d.verbose
		d.mu.RUnlock()

		if verbose {
			gologger.Verbose().Msgf("Honeypot detected: %s (matched %d distinct templates)", host, len(entry.templates))
		}
		return true
	}

	return false
}

// IsHoneypot checks if a host has been flagged as a honeypot.
func (d *Detector) IsHoneypot(host string) bool {
	if host == "" {
		return false
	}

	d.mu.RLock()
	entry, exists := d.cache.Get(host)
	d.mu.RUnlock()

	if !exists {
		return false
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.flagged
}

// GetMatchCount returns the number of distinct template matches for a host.
func (d *Detector) GetMatchCount(host string) int {
	if host == "" {
		return 0
	}

	d.mu.RLock()
	entry, exists := d.cache.Get(host)
	d.mu.RUnlock()

	if !exists {
		return 0
	}

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
	d.mu.RLock()
	defer d.mu.RUnlock()

	var flagged []string
	for _, host := range d.cache.Keys() {
		entry, exists := d.cache.Peek(host)
		if exists {
			entry.mu.Lock()
			if entry.flagged {
				flagged = append(flagged, host)
			}
			entry.mu.Unlock()
		}
	}
	return flagged
}

// Close cleans up resources used by the detector.
func (d *Detector) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache.Purge()
}

// LoadBlocklist loads known honeypot hosts from a file and pre-flags them.
// Each line in the file should contain one host (blank lines and # comments are ignored).
// Returns the number of hosts loaded and any error encountered.
func (d *Detector) LoadBlocklist(filepath string) (int, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var count int
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
		// Pre-flag this host as a honeypot
		d.preFlagHost(line)
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, err
	}

	if count > 0 {
		gologger.Info().Msgf("Loaded %d known honeypot hosts from blocklist", count)
	}

	return count, nil
}

// preFlagHost adds a host to the cache and marks it as a honeypot.
// This is used for loading blocklists of known honeypots.
func (d *Detector) preFlagHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}

	d.mu.Lock()
	entry, exists := d.cache.Get(host)
	if !exists {
		entry = &hostEntry{
			templates: make(map[string]struct{}),
		}
		d.cache.Add(host, entry)
	}
	d.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if !entry.flagged {
		entry.flagged = true
		// Mark as pre-loaded blocklist entry
		entry.templates["__blocklist__"] = struct{}{}
		d.honeypotCount.Add(1)
	}
}
