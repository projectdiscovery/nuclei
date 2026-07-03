package honeypotdetector

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// Detector tracks honeypot likelihood by counting distinct template matches per normalized host.
// Once a host reaches the configured threshold, it becomes flagged.
type Detector struct {
	threshold int
	hosts     sync.Map // map[normalizedHost]*hostState
}

type hostState struct {
	mu          sync.Mutex
	templateIDs map[string]struct{}
	flagged     bool
}

// New creates a new honeypot detector.
func New(threshold int) *Detector {
	if threshold <= 0 {
		threshold = 1
	}
	return &Detector{
		threshold: threshold,
	}
}

// Threshold returns the distinct template count required to flag a host.
func (d *Detector) Threshold() int {
	if d == nil {
		return 0
	}
	return d.threshold
}

// RecordMatch records a match for the given host and templateID.
//
// It returns true only when the host has just become flagged (i.e. crossed the threshold).
func (d *Detector) RecordMatch(host, templateID string) bool {
	if d == nil {
		return false
	}

	normalizedHost := normalizeHostKey(host)
	if normalizedHost == "" || templateID == "" {
		return false
	}

	stateAny, _ := d.hosts.LoadOrStore(normalizedHost, &hostState{
		templateIDs: make(map[string]struct{}),
	})
	state := stateAny.(*hostState)

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.flagged {
		return false
	}
	if _, ok := state.templateIDs[templateID]; ok {
		return false
	}

	state.templateIDs[templateID] = struct{}{}
	if len(state.templateIDs) >= d.threshold {
		state.flagged = true
		state.templateIDs = nil
		return true
	}
	return false
}

// IsFlagged returns whether the given host is flagged.
func (d *Detector) IsFlagged(host string) bool {
	if d == nil {
		return false
	}

	normalizedHost := normalizeHostKey(host)
	if normalizedHost == "" {
		return false
	}

	stateAny, ok := d.hosts.Load(normalizedHost)
	if !ok {
		return false
	}
	state := stateAny.(*hostState)

	state.mu.Lock()
	defer state.mu.Unlock()
	return state.flagged
}

// Summary returns a short string with the total number of flagged hosts.
func (d *Detector) Summary() string {
	if d == nil {
		return "honeypot-detected hosts: 0"
	}

	var flagged int
	d.hosts.Range(func(_, v any) bool {
		state := v.(*hostState)
		state.mu.Lock()
		if state.flagged {
			flagged++
		}
		state.mu.Unlock()
		return true
	})

	return fmt.Sprintf("honeypot-detected hosts: %d", flagged)
}

// NormalizeHostKey normalizes host strings so different input formats map to the same key.
func NormalizeHostKey(input string) string {
	return normalizeHostKey(input)
}

func normalizeHostKey(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}

	// Strip trailing slashes early.
	s = strings.TrimRight(s, "/")

	// If an absolute URL is present, parse it to reliably extract host and optional port.
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err == nil && u != nil {
			host := u.Hostname()
			port := u.Port()
			if host == "" {
				return ""
			}
			host = normalizeHostWithoutPort(host)
			if port != "" {
				return net.JoinHostPort(host, port)
			}
			return host
		}
		// fall through if parsing fails
	}

	// Remove any path suffix (we only care about the authority).
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}

	// If it looks like host:port (including bracketed IPv6), try SplitHostPort first.
	if host, port, err := net.SplitHostPort(s); err == nil {
		host = normalizeHostWithoutPort(host)
		if port == "" {
			return host
		}
		return net.JoinHostPort(host, port)
	}

	// Handle bracketed IPv6 without port: [2001:db8::1]
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
		return normalizeHostWithoutPort(host)
	}

	// Handle bare IPv6 or host without port.
	return normalizeHostWithoutPort(s)
}

func normalizeHostWithoutPort(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.ToLower(h)

	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return h
}
