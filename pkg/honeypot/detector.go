package honeypot

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// Detector tracks unique template matches per normalized host and flags honeypots.
type Detector struct {
	threshold int
	mu        sync.RWMutex
	matches   map[string]map[string]struct{}
	flagged   map[string]bool
}

// NewDetector creates a Detector with a given threshold (<=0 disables detection).
func NewDetector(threshold int) *Detector {
	return &Detector{
		threshold: threshold,
		matches:   make(map[string]map[string]struct{}),
		flagged:   make(map[string]bool),
	}
}

// NormalizeHost canonicalizes a raw host/URL string: strips scheme, userinfo, port, brackets, lowercases.
func NormalizeHost(raw string) string {
	u, err := url.Parse(raw)
	host := raw
	if err == nil && u.Host != "" {
		host = u.Host
	}
	// drop userinfo
	if at := strings.LastIndex(host, "@"); at != -1 {
		host = host[at+1:]
	}
	host = strings.ToLower(host)
	// strip port
	h, pErr := net.SplitHostPort(host)
	if pErr == nil {
		host = h
	}
	// strip IPv6 brackets
	host = strings.Trim(host, "[]")
	return host
}

// RecordMatch records a template match for rawHost and returns true if host is flagged.
func (d *Detector) RecordMatch(rawHost, templateID string) bool {
	if d == nil || d.threshold <= 0 {
		return false
	}
	host := NormalizeHost(rawHost)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flagged[host] {
		return true
	}
	set, ok := d.matches[host]
	if !ok {
		set = make(map[string]struct{})
		d.matches[host] = set
	}
	set[templateID] = struct{}{}
	if len(set) >= d.threshold {
		d.flagged[host] = true
		gologger.Warning().Msgf("Host %s flagged as potential honeypot (>= %d unique matches)", host, d.threshold)
		return true
	}
	return false
}

// IsFlagged returns whether rawHost has been flagged as honeypot.
func (d *Detector) IsFlagged(rawHost string) bool {
	if d == nil || d.threshold <= 0 {
		return false
	}
	host := NormalizeHost(rawHost)
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.flagged[host]
}