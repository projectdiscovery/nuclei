package output

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// SessionData stores information about a host's template execution sessions
type SessionData struct {
	TemplateIDs map[string]struct{} // Set of template IDs executed on this host
	FirstSeen   time.Time           // When this host was first tracked
	LastSeen    time.Time           // When this host was last accessed
}

// HoneypotTracker tracks template executions per host using LRU cache to detect potential honeypots.
// It implements thread-safe LRU eviction to maintain bounded memory usage while preventing
// silent failures when capacity limits are reached.
type HoneypotTracker struct {
	sync.RWMutex
	sessions    map[string]*SessionData // LRU cache of host sessions
	order       []string                // LRU order tracking (oldest at index 0)
	capacity    int                     // Maximum number of hosts to track
	warnedHosts map[string]struct{}     // Tracks hosts that have already triggered honeypot warnings
	limitWarned bool                    // Indicates if capacity limit warning has been logged
}

// NewHoneypotTracker creates a new thread-safe honeypot tracker with specified capacity.
// Parameters:
//   - capacity: Maximum number of hosts to track (default: 10000 if <= 0)
//
// Returns a pointer to the newly created HoneypotTracker ready for use.
func NewHoneypotTracker(capacity int) *HoneypotTracker {
	if capacity <= 0 {
		capacity = 10000 // Default capacity
	}
	
	return &HoneypotTracker{
		sessions:    make(map[string]*SessionData),
		order:       make([]string, 0, capacity),
		capacity:    capacity,
		warnedHosts: make(map[string]struct{}),
	}
}

// AddSession adds a template execution for a host and returns honeypot detection status.
// 
// Parameters:
//   - host: The hostname or URL to track template execution for
//   - templateID: The unique identifier of the template being executed
//
// Returns:
//   - bool: isHoneypot - True if this host appears to be a honeypot (>10 unique templates)
//   - bool: isFirstTime - True if this is the first time detecting this host as a honeypot
//
// The function implements LRU eviction when capacity limits are reached to prevent silent failures.
// It safely parses hostnames, strips ports, and maintains thread-safe access to tracking data.
func (ht *HoneypotTracker) AddSession(host, templateID string) (bool, bool) {
	host = ht.normalizeHost(host)
	if host == "" {
		return false, false
	}
	
	ht.Lock()
	defer ht.Unlock()
	
	now := time.Now()
	isNewHost := ht.sessions[host] == nil
	
	// Initialize new host session
	if isNewHost {
		// Check memory limit and evict if needed
		if len(ht.sessions) >= ht.capacity {
			ht.evictOldest()
		}
		
		ht.sessions[host] = &SessionData{
			TemplateIDs: make(map[string]struct{}),
			FirstSeen:   now,
			LastSeen:    now,
		}
		// Add to LRU order (new hosts are most recent)
		ht.order = append(ht.order, host)
	} else {
		// Update existing host - move to most recent position
		ht.moveToEnd(host)
		ht.sessions[host].LastSeen = now
	}
	
	// Add template ID to host's session
	ht.sessions[host].TemplateIDs[templateID] = struct{}{}
	
	// Check if this host is a honeypot (more than 10 unique templates)
	isHoneypot := len(ht.sessions[host].TemplateIDs) > 10
	
	// Check if we've warned about this host before
	_, hasWarned := ht.warnedHosts[host]
	if !hasWarned && isHoneypot {
		// Mark this host as warned
		ht.warnedHosts[host] = struct{}{}
		return true, true // isHoneypot, isFirstTime
	}
	
	return isHoneypot, false
}

// GetSession retrieves session data for a host.
// Parameters:
//   - host: The hostname to retrieve session data for
//
// Returns the SessionData and a boolean indicating if the host exists.
// This method is thread-safe and updates the host's position in LRU order.
func (ht *HoneypotTracker) GetSession(host string) (*SessionData, bool) {
	host = ht.normalizeHost(host)
	if host == "" {
		return nil, false
	}
	
	ht.Lock()
	defer ht.Unlock()
	
	session, exists := ht.sessions[host]
	if !exists {
		return nil, false
	}
	
	// Move to end (most recently used)
	ht.moveToEnd(host)
	session.LastSeen = time.Now()
	
	return session, true
}

// GetStats returns statistics about the honeypot tracker.
// Returns:
//   - int: Total number of tracked hosts
//   - int: Number of hosts warned as potential honeypots
//   - int: Current capacity limit
func (ht *HoneypotTracker) GetStats() (int, int, int) {
	ht.RLock()
	defer ht.RUnlock()
	
	return len(ht.sessions), len(ht.warnedHosts), ht.capacity
}

// normalizeHost normalizes a hostname by parsing URLs and extracting the hostname.
// Parameters:
//   - host: The hostname or URL to normalize
//
// Returns the normalized hostname or empty string if invalid.
func (ht *HoneypotTracker) normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	
	// Check if raw host string contains :// to detect scheme
	if !strings.Contains(host, "://") {
		// If no scheme, check if it's bare IPv6 and wrap in brackets
		rawHost := strings.TrimSpace(host)
		if strings.Count(rawHost, ":") >= 2 && !strings.HasPrefix(rawHost, "[") {
			rawHost = "[" + rawHost + "]"
		}
		// If no scheme, prepend http:// before parsing
		host = "http://" + rawHost
	}
	
	// Parse host using net/url to prevent path bypass
	parsedURL, err := url.Parse(host)
	if err != nil {
		// Return error or skip - do NOT fall back to insecure parsing
		return ""
	}
	
	// Use hostname from the parsed URL to prevent path bypass
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return ""
	}
	
	return hostname
}

// evictOldest removes the least recently used host from the tracker.
// This method is NOT thread-safe and should only be called while holding the write lock.
func (ht *HoneypotTracker) evictOldest() {
	if len(ht.order) == 0 {
		return
	}
	
	oldestHost := ht.order[0]
	// Remove from all tracking structures
	delete(ht.sessions, oldestHost)
	delete(ht.warnedHosts, oldestHost)
	// Remove from order slice and shift remaining elements
	ht.order = ht.order[1:]
	
	// Log eviction for transparency
	if !ht.limitWarned {
		ht.limitWarned = true
		gologger.Warning().Msgf("Honeypot tracker memory limit reached (%d hosts), evicting oldest host '%s' to make room", ht.capacity, oldestHost)
	}
}

// moveToEnd moves a host to the end of the LRU order (most recently used position).
// This method is NOT thread-safe and should only be called while holding the write lock.
func (ht *HoneypotTracker) moveToEnd(host string) {
	for i, existingHost := range ht.order {
		if existingHost == host {
			// Remove from current position
			ht.order = append(ht.order[:i], ht.order[i+1:]...)
			// Append to end (most recently used)
			ht.order = append(ht.order, host)
			break
		}
	}
}

// Clear removes all tracked hosts and resets the tracker.
// This method is thread-safe.
func (ht *HoneypotTracker) Clear() {
	ht.Lock()
	defer ht.Unlock()
	
	ht.sessions = make(map[string]*SessionData)
	ht.order = make([]string, 0, ht.capacity)
	ht.warnedHosts = make(map[string]struct{})
	ht.limitWarned = false
}
