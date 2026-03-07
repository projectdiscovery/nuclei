package output

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

// HoneypotDetector tracks matches per host to detect potential honeypots.
type HoneypotDetector struct {
	mu        sync.Mutex
	options   *types.Options
	matches   map[string]map[string]struct{} // host -> templateID -> exists
	threshold int
	warned    sync.Map // host -> struct{}
}

// NewHoneypotDetector creates a new HoneypotDetector instance.
func NewHoneypotDetector(options *types.Options) *HoneypotDetector {
	threshold := options.HoneypotThreshold
	if threshold <= 0 {
		threshold = 20
	}
	if options.DetectHoneypot {
	}
	return &HoneypotDetector{
		options:   options,
		matches:   make(map[string]map[string]struct{}),
		threshold: threshold,
	}
}

// normalizeHost ensures example.com:443 and example.com map to the same entity.
func normalizeHost(host string) string {
	if host == "" {
		return ""
	}
	// urlutil.Parse expects a scheme for consistent hostname extraction
	rawHost := host
	if !strings.Contains(rawHost, "://") {
		rawHost = "http://" + rawHost
	}
	u, err := urlutil.Parse(rawHost)
	if err != nil {
		return host
	}
	return u.Hostname()
}

// AddMatch increments the template match count for a given host.
func (h *HoneypotDetector) AddMatch(host, templateID string) {
	if !h.options.DetectHoneypot || host == "" {
		return
	}

	normalizedHost := normalizeHost(host)

	// Fast path: if we already flagged this host, skip tracking lock-free.
	if _, ok := h.warned.Load(normalizedHost); ok {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check under lock
	if _, ok := h.warned.Load(normalizedHost); ok {
		return
	}

	if h.matches[normalizedHost] == nil {
		h.matches[normalizedHost] = make(map[string]struct{})
	}
	h.matches[normalizedHost][templateID] = struct{}{}

	if len(h.matches[normalizedHost]) >= h.threshold {
		gologger.Warning().Msgf("[HONEYPOT?] %s matched %d templates — results may be unreliable", normalizedHost, len(h.matches[normalizedHost]))

		// Mark as warned and free tracking memory for this host
		h.warned.Store(normalizedHost, struct{}{})
		delete(h.matches, normalizedHost)
	}
}
