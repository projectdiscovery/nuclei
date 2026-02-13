package honeypot

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
)

const (
	// DefaultThreshold is the default number of unique template matches
	// before a host is flagged as a potential honeypot.
	DefaultThreshold = 10
)

// Detector tracks unique template matches per host and flags
// hosts that exceed a configurable threshold as potential honeypots.
// It is safe for concurrent use.
type Detector struct {
	threshold int
	hosts     sync.Map // host string -> *hostEntry
	flagged   atomic.Int32
	enabled   bool
}

// hostEntry tracks the set of unique template IDs matched for a host.
type hostEntry struct {
	mu          sync.Mutex
	templateIDs map[string]struct{}
	flagged     bool
}

// New creates a new honeypot detector with the given threshold.
// If threshold <= 0, detection is disabled.
func New(threshold int) *Detector {
	return &Detector{
		threshold: threshold,
		enabled:   threshold > 0,
	}
}

// IsEnabled returns whether honeypot detection is active.
func (d *Detector) IsEnabled() bool {
	return d.enabled
}

// RecordMatch records that the given template matched the given host.
// Returns true if this match caused the host to be newly flagged as a honeypot.
func (d *Detector) RecordMatch(host, templateID string) bool {
	if !d.enabled {
		return false
	}

	host = normalizeHost(host)
	if host == "" {
		return false
	}

	actual, _ := d.hosts.LoadOrStore(host, &hostEntry{
		templateIDs: make(map[string]struct{}),
	})
	entry := actual.(*hostEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.flagged {
		// Already flagged — still record the template but don't re-flag
		entry.templateIDs[templateID] = struct{}{}
		return false
	}

	entry.templateIDs[templateID] = struct{}{}

	if len(entry.templateIDs) >= d.threshold {
		entry.flagged = true
		d.flagged.Add(1)
		gologger.Warning().Msgf("Potential honeypot detected: %s (%d unique template matches exceeded threshold of %d)", host, len(entry.templateIDs), d.threshold)
		return true
	}
	return false
}

// IsHoneypot returns whether the given host has been flagged as a honeypot.
func (d *Detector) IsHoneypot(host string) bool {
	if !d.enabled {
		return false
	}

	host = normalizeHost(host)
	if host == "" {
		return false
	}

	actual, ok := d.hosts.Load(host)
	if !ok {
		return false
	}
	entry := actual.(*hostEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.flagged
}

// GetMatchCount returns the number of unique template matches for a host.
func (d *Detector) GetMatchCount(host string) int {
	if !d.enabled {
		return 0
	}

	host = normalizeHost(host)
	if host == "" {
		return 0
	}

	actual, ok := d.hosts.Load(host)
	if !ok {
		return 0
	}
	entry := actual.(*hostEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return len(entry.templateIDs)
}

// FlaggedCount returns the total number of flagged honeypot hosts.
func (d *Detector) FlaggedCount() int {
	if !d.enabled {
		return 0
	}
	return int(d.flagged.Load())
}

// FlaggedHosts returns all hosts that have been flagged as honeypots
// along with their match counts.
func (d *Detector) FlaggedHosts() map[string]int {
	result := make(map[string]int)
	if !d.enabled {
		return result
	}
	d.hosts.Range(func(key, value any) bool {
		host := key.(string)
		entry := value.(*hostEntry)
		entry.mu.Lock()
		if entry.flagged {
			result[host] = len(entry.templateIDs)
		}
		entry.mu.Unlock()
		return true
	})
	return result
}

// normalizeHost extracts and lowercases the host portion from a URL or host:port string.
func normalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// Strip scheme if present
	if idx := strings.Index(input, "://"); idx != -1 {
		input = input[idx+3:]
	}

	// Strip leading slashes (e.g. protocol-relative "//host")
	input = strings.TrimLeft(input, "/")

	// Strip path
	if idx := strings.IndexByte(input, '/'); idx != -1 {
		input = input[:idx]
	}

	// Strip query
	if idx := strings.IndexByte(input, '?'); idx != -1 {
		input = input[:idx]
	}

	// Strip fragment
	if idx := strings.IndexByte(input, '#'); idx != -1 {
		input = input[:idx]
	}

	// Strip userinfo (user:pass@)
	if idx := strings.LastIndex(input, "@"); idx != -1 {
		input = input[idx+1:]
	}

	// Handle IPv6 brackets
	if strings.HasPrefix(input, "[") {
		if host, _, err := net.SplitHostPort(input); err == nil {
			return strings.ToLower(host)
		}
		// Bracketed but no port — strip brackets
		input = strings.Trim(input, "[]")
		return strings.ToLower(input)
	}

	// Strip port for host:port
	if host, _, err := net.SplitHostPort(input); err == nil {
		return strings.ToLower(host)
	}

	return strings.ToLower(input)
}
