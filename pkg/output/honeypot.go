package output

import (
	"net"
	"strings"
	"sync"

	urlutil "github.com/projectdiscovery/utils/url"
)

type honeypotDecision struct {
	host         string
	count        int
	newlyFlagged bool
	suppress     bool
}

type honeypotDetector struct {
	threshold int
	suppress  bool

	mu          sync.Mutex
	hostMatches map[string]map[string]struct{}
	flagged     map[string]struct{}
}

func newHoneypotDetector(threshold int, suppress bool) *honeypotDetector {
	if threshold <= 0 {
		return nil
	}
	return &honeypotDetector{
		threshold:   threshold,
		suppress:    suppress,
		hostMatches: make(map[string]map[string]struct{}),
		flagged:     make(map[string]struct{}),
	}
}

func (d *honeypotDetector) evaluate(event *ResultEvent) honeypotDecision {
	if d == nil || event == nil || event.TemplateID == "" {
		return honeypotDecision{}
	}

	host := normalizeHoneypotHost(event)
	if host == "" {
		return honeypotDecision{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, alreadyFlagged := d.flagged[host]; alreadyFlagged {
		return honeypotDecision{host: host, suppress: d.suppress}
	}

	templates, ok := d.hostMatches[host]
	if !ok {
		templates = make(map[string]struct{})
		d.hostMatches[host] = templates
	}
	templates[event.TemplateID] = struct{}{}

	count := len(templates)
	if count < d.threshold {
		return honeypotDecision{host: host, count: count}
	}

	d.flagged[host] = struct{}{}
	delete(d.hostMatches, host)

	// The event that crosses threshold should still be emitted.
	return honeypotDecision{
		host:         host,
		count:        count,
		newlyFlagged: true,
		suppress:     false,
	}
}

func normalizeHoneypotHost(event *ResultEvent) string {
	for _, candidate := range []string{event.Host, event.URL} {
		host := normalizeHostCandidate(candidate)
		if host != "" {
			return host
		}
	}
	return ""
}

func normalizeHostCandidate(candidate string) string {
	value := strings.TrimSpace(candidate)
	if value == "" {
		return ""
	}

	if parsed, err := urlutil.ParseAbsoluteURL(value, false); err == nil && parsed != nil {
		host := strings.ToLower(parsed.Hostname())
		if host != "" {
			return host
		}
	}

	if schemeIdx := strings.Index(value, "://"); schemeIdx != -1 {
		value = value[schemeIdx+3:]
	}
	if idx := strings.IndexAny(value, "/?#"); idx != -1 {
		value = value[:idx]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}
