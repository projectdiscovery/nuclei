package output

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

// DefaultHoneypotThreshold is the default number of unique template matches
// per host above which the host is flagged as a potential honeypot.
const DefaultHoneypotThreshold = 100

// HoneypotWriter wraps an output Writer to track the number of unique
// template matches per host. Hosts exceeding the configured threshold
// are flagged as potential honeypots in the scan summary.
//
// When ExcludeHoneypotResults is true, results for flagged hosts are
// suppressed from output entirely; otherwise they are written normally
// but the user is warned at scan completion.
type HoneypotWriter struct {
	inner     Writer
	threshold int
	exclude   bool
	logger    *gologger.Logger

	mu sync.Mutex
	// hostMatches tracks unique template IDs matched per host.
	hostMatches map[string]map[string]struct{}
	// hostResults buffers results when exclusion mode is on.
	hostResults map[string][]*ResultEvent
}

// HoneypotWriterOptions contains options for honeypot detection.
type HoneypotWriterOptions struct {
	// Inner is the underlying writer to delegate to.
	Inner Writer
	// Threshold is the minimum number of unique template matches
	// on a single host that triggers honeypot detection.
	// A value of 0 means the default threshold is used.
	Threshold int
	// ExcludeResults when true suppresses results for detected honeypots.
	ExcludeResults bool
	// Logger is the logger instance.
	Logger *gologger.Logger
}

var _ Writer = &HoneypotWriter{}

// NewHoneypotWriter creates a new HoneypotWriter wrapping the provided writer.
func NewHoneypotWriter(opts HoneypotWriterOptions) *HoneypotWriter {
	threshold := opts.Threshold
	if threshold <= 0 {
		threshold = DefaultHoneypotThreshold
	}
	return &HoneypotWriter{
		inner:       opts.Inner,
		threshold:   threshold,
		exclude:     opts.ExcludeResults,
		logger:      opts.Logger,
		hostMatches: make(map[string]map[string]struct{}),
		hostResults: make(map[string][]*ResultEvent),
	}
}

// Write intercepts result events to track matches per host. If exclusion
// mode is enabled, results for hosts that already exceed the threshold
// are dropped. Otherwise, all results are forwarded to the inner writer.
func (hw *HoneypotWriter) Write(event *ResultEvent) error {
	if event == nil {
		return nil
	}
	host := extractHost(event)
	templateID := event.TemplateID

	hw.mu.Lock()
	if hw.hostMatches[host] == nil {
		hw.hostMatches[host] = make(map[string]struct{})
	}
	hw.hostMatches[host][templateID] = struct{}{}
	matchCount := len(hw.hostMatches[host])

	if hw.exclude {
		// Buffer results to potentially drop them if the host turns out
		// to be a honeypot. Once the threshold is crossed, stop buffering
		// and silently discard future results for this host.
		if matchCount > hw.threshold {
			// Already flagged -- discard silently
			hw.mu.Unlock()
			return nil
		}
		if matchCount == hw.threshold {
			// Just crossed the threshold -- discard buffered results and this one
			hw.logger.Warning().Msgf("[honeypot] Host %s exceeded threshold (%d unique template matches) - dropping results", host, hw.threshold)
			delete(hw.hostResults, host)
			hw.mu.Unlock()
			return nil
		}
		// Below threshold -- buffer and forward
		hw.hostResults[host] = append(hw.hostResults[host], event)
		hw.mu.Unlock()
		return hw.inner.Write(event)
	}

	hw.mu.Unlock()
	return hw.inner.Write(event)
}

// WriteFailure forwards failure events to the inner writer.
func (hw *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return hw.inner.WriteFailure(event)
}

// Request forwards request logs to the inner writer.
func (hw *HoneypotWriter) Request(templateID, url, requestType string, err error) {
	hw.inner.Request(templateID, url, requestType, err)
}

// RequestStatsLog forwards stats log to the inner writer.
func (hw *HoneypotWriter) RequestStatsLog(statusCode, response string) {
	hw.inner.RequestStatsLog(statusCode, response)
}

// WriteStoreDebugData forwards debug data to the inner writer.
func (hw *HoneypotWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	hw.inner.WriteStoreDebugData(host, templateID, eventType, data)
}

// Colorizer returns the colorizer from the inner writer.
func (hw *HoneypotWriter) Colorizer() aurora.Aurora {
	return hw.inner.Colorizer()
}

// ResultCount returns result count from the inner writer.
func (hw *HoneypotWriter) ResultCount() int {
	return hw.inner.ResultCount()
}

// Close prints the honeypot detection summary and closes the inner writer.
func (hw *HoneypotWriter) Close() {
	hw.printHoneypotSummary()
	hw.inner.Close()
}

// GetDetectedHoneypots returns a map of hosts detected as potential
// honeypots and the number of unique template matches for each.
func (hw *HoneypotWriter) GetDetectedHoneypots() map[string]int {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	detected := make(map[string]int)
	for host, templates := range hw.hostMatches {
		if len(templates) >= hw.threshold {
			detected[host] = len(templates)
		}
	}
	return detected
}

// printHoneypotSummary prints detected honeypots at scan completion.
func (hw *HoneypotWriter) printHoneypotSummary() {
	detected := hw.GetDetectedHoneypots()
	if len(detected) == 0 {
		hw.logger.Info().Msgf("[honeypot] No potential honeypots detected (threshold: %d)", hw.threshold)
		return
	}

	// Sort by match count descending for readable output
	type hostEntry struct {
		Host  string
		Count int
	}
	entries := make([]hostEntry, 0, len(detected))
	for host, count := range detected {
		entries = append(entries, hostEntry{Host: host, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[honeypot] Detected %d potential honeypot(s) (threshold: %d unique template matches):\n", len(entries), hw.threshold))
	for _, e := range entries {
		action := "results included"
		if hw.exclude {
			action = "results excluded"
		}
		sb.WriteString(fmt.Sprintf("  - %s: %d unique matches (%s)\n", e.Host, e.Count, action))
	}
	hw.logger.Warning().Msgf("%s", sb.String())
}

// extractHost returns the best available host identifier from a ResultEvent.
func extractHost(event *ResultEvent) string {
	if event.Host != "" {
		return event.Host
	}
	if event.IP != "" {
		return event.IP
	}
	if event.URL != "" {
		return event.URL
	}
	return "unknown"
}
