package output

import (
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/honeypot"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// HoneypotWriter wraps a Writer and intercepts results to track
// template matches per host. When a host exceeds the configured
// threshold of distinct template matches, its results are suppressed
// and a warning is logged.
type HoneypotWriter struct {
	inner    Writer
	detector *honeypot.Detector
	// warned tracks hosts for which we already printed a warning,
	// to avoid flooding the user with repeated messages.
	warned *mapsutil.SyncLockMap[string, struct{}]
	// warnMu serializes the check+set+log sequence to prevent
	// duplicate warnings from concurrent Write calls.
	warnMu sync.Mutex
}

var _ Writer = &HoneypotWriter{}

// NewHoneypotWriter creates a HoneypotWriter that wraps the given
// writer with honeypot detection. If the detector is nil or disabled,
// the inner writer is returned directly.
func NewHoneypotWriter(inner Writer, detector *honeypot.Detector) Writer {
	if !detector.Enabled() {
		return inner
	}
	return &HoneypotWriter{
		inner:    inner,
		detector: detector,
		warned:   mapsutil.NewSyncLockMap[string, struct{}](),
	}
}

// Write records the result against the honeypot detector and either
// passes it through to the inner writer or suppresses it if the
// host has been flagged.
func (hw *HoneypotWriter) Write(event *ResultEvent) error {
	host := event.Host
	if host == "" {
		host = event.URL
	}
	if host == "" {
		// No host information -- pass through
		return hw.inner.Write(event)
	}

	flagged := hw.detector.Record(host, event.TemplateID)
	if flagged {
		// Use the same normalization the detector applies internally so
		// that different representations of the same host (scheme, case,
		// default-port URLs) share a single warned-map entry.
		normalizedHost := honeypot.NormalizeHost(host)

		// Serialize check+set to prevent duplicate warnings from
		// concurrent Write calls on the same host.
		hw.warnMu.Lock()
		alreadyWarned := hw.warned.Has(normalizedHost)
		if !alreadyWarned {
			_ = hw.warned.Set(normalizedHost, struct{}{})
		}
		hw.warnMu.Unlock()

		if !alreadyWarned {
			count := hw.detector.MatchCount(host)
			gologger.Warning().Msgf(
				"[honeypot] Host %s matched %d templates, exceeding threshold -- likely honeypot, suppressing results",
				host, count,
			)
		}
		return nil // suppress
	}

	return hw.inner.Write(event)
}

func (hw *HoneypotWriter) WriteFailure(event *InternalWrappedEvent) error {
	return hw.inner.WriteFailure(event)
}

func (hw *HoneypotWriter) Close() {
	// Print summary of flagged hosts
	if summary := hw.detector.Summary(); summary != "" {
		gologger.Info().Msgf("\n%s", summary)
	}
	hw.inner.Close()
}

func (hw *HoneypotWriter) Colorizer() aurora.Aurora {
	return hw.inner.Colorizer()
}

func (hw *HoneypotWriter) Request(templateID, url, requestType string, err error) {
	hw.inner.Request(templateID, url, requestType, err)
}

func (hw *HoneypotWriter) RequestStatsLog(statusCode, response string) {
	hw.inner.RequestStatsLog(statusCode, response)
}

func (hw *HoneypotWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	hw.inner.WriteStoreDebugData(host, templateID, eventType, data)
}

func (hw *HoneypotWriter) ResultCount() int {
	return hw.inner.ResultCount()
}
