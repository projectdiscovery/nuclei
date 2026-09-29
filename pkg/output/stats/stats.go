// Package stats provides a stats tracker for tracking Status Codes,
// Errors & WAF detection events.
//
// It is wrapped and called by output.Writer interface.
package stats

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/output/stats/waf"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var sharedWafDetector = sync.OnceValue(waf.NewWafDetector)

// Tracker is a stats tracker instance for nuclei scans
type Tracker struct {
	// counters for various stats
	statusCodes *mapsutil.SyncLockMap[string, *atomic.Int32]
	errorCodes  *mapsutil.SyncLockMap[string, *atomic.Int32]
	wafDetected *mapsutil.SyncLockMap[string, *atomic.Int32]
	wafCalls    atomic.Uint64
	wafBytes    atomic.Uint64
	wafRegexes  atomic.Uint64
	wafSkips    atomic.Uint64
	wafDuration atomic.Uint64

	// internal stuff
	wafDetector *waf.WafDetector
}

// NewTracker creates a new Tracker instance.
func NewTracker() *Tracker {
	return &Tracker{
		statusCodes: mapsutil.NewSyncLockMap[string, *atomic.Int32](),
		errorCodes:  mapsutil.NewSyncLockMap[string, *atomic.Int32](),
		wafDetected: mapsutil.NewSyncLockMap[string, *atomic.Int32](),
		wafDetector: sharedWafDetector(),
	}
}

// TrackStatusCode tracks the status code of a request
func (t *Tracker) TrackStatusCode(statusCode string) {
	t.incrementCounter(t.statusCodes, statusCode)
}

// TrackErrorKind tracks the error kind of a request
func (t *Tracker) TrackErrorKind(errKind string) {
	t.incrementCounter(t.errorCodes, errKind)
}

// TrackWAFDetected tracks the waf detected of a request
//
// First it detects if a waf is running and if so, it increments
// the counter for the waf.
func (t *Tracker) TrackWAFDetected(httpResponse string) {
	started := time.Now()
	id, ok, detectionStats := t.wafDetector.DetectWAFWithStats(httpResponse)
	t.wafCalls.Add(1)
	t.wafBytes.Add(uint64(len(httpResponse)))
	t.wafRegexes.Add(uint64(detectionStats.RegexEvaluations))
	t.wafSkips.Add(uint64(detectionStats.PrefilterSkips))
	t.wafDuration.Add(uint64(time.Since(started)))
	if !ok {
		return
	}

	t.incrementCounter(t.wafDetected, id)
}

// WAFMetrics reports execution-local WAF analysis work. It is separate from
// StatsOutput because it is operational telemetry rather than customer-facing
// scan statistics.
type WAFMetrics struct {
	Calls            uint64
	Bytes            uint64
	RegexEvaluations uint64
	PrefilterSkips   uint64
	Duration         time.Duration
}

// GetWAFMetrics returns an atomic snapshot suitable for progress logging while
// requests are still executing.
func (t *Tracker) GetWAFMetrics() WAFMetrics {
	return WAFMetrics{
		Calls:            t.wafCalls.Load(),
		Bytes:            t.wafBytes.Load(),
		RegexEvaluations: t.wafRegexes.Load(),
		PrefilterSkips:   t.wafSkips.Load(),
		Duration:         time.Duration(t.wafDuration.Load()),
	}
}

func (t *Tracker) incrementCounter(m *mapsutil.SyncLockMap[string, *atomic.Int32], key string) {
	if counter, ok := m.Get(key); ok {
		counter.Add(1)
	} else {
		newCounter := new(atomic.Int32)
		newCounter.Store(1)
		_ = m.Set(key, newCounter)
	}
}

type StatsOutput struct {
	StatusCodeStats map[string]int `json:"status_code_stats"`
	ErrorStats      map[string]int `json:"error_stats"`
	WAFStats        map[string]int `json:"waf_stats"`
}

func (t *Tracker) GetStats() *StatsOutput {
	stats := &StatsOutput{
		StatusCodeStats: make(map[string]int),
		ErrorStats:      make(map[string]int),
		WAFStats:        make(map[string]int),
	}
	_ = t.errorCodes.Iterate(func(k string, v *atomic.Int32) error {
		stats.ErrorStats[k] = int(v.Load())
		return nil
	})
	_ = t.statusCodes.Iterate(func(k string, v *atomic.Int32) error {
		stats.StatusCodeStats[k] = int(v.Load())
		return nil
	})
	_ = t.wafDetected.Iterate(func(k string, v *atomic.Int32) error {
		waf, ok := t.wafDetector.GetWAF(k)
		if !ok {
			return nil
		}
		stats.WAFStats[waf.Name] = int(v.Load())
		return nil
	})
	return stats
}

// DisplayTopStats prints the most relevant statistics for CLI
func (t *Tracker) DisplayTopStats(noColor bool) {
	stats := t.GetStats()

	if len(stats.StatusCodeStats) > 0 {
		fmt.Printf("\n%s\n", aurora.Bold(aurora.Blue("Top Status Codes:")))
		topStatusCodes := getTopN(stats.StatusCodeStats, 6)
		for _, item := range topStatusCodes {
			if noColor {
				fmt.Printf("  %s: %d\n", item.Key, item.Value)
			} else {
				color := getStatusCodeColor(item.Key)
				fmt.Printf("  %s: %d\n", aurora.Colorize(item.Key, color), item.Value)
			}
		}
	}

	if len(stats.ErrorStats) > 0 {
		fmt.Printf("\n%s\n", aurora.Bold(aurora.Red("Top Errors:")))
		topErrors := getTopN(stats.ErrorStats, 5)
		for _, item := range topErrors {
			if noColor {
				fmt.Printf("  %s: %d\n", item.Key, item.Value)
			} else {
				fmt.Printf("  %s: %d\n", aurora.Red(item.Key), item.Value)
			}
		}
	}

	if len(stats.WAFStats) > 0 {
		fmt.Printf("\n%s\n", aurora.Bold(aurora.Yellow("WAF Detections:")))
		for name, count := range stats.WAFStats {
			if noColor {
				fmt.Printf("  %s: %d\n", name, count)
			} else {
				fmt.Printf("  %s: %d\n", aurora.Yellow(name), count)
			}
		}
	}
}

// Helper struct for sorting
type kv struct {
	Key   string
	Value int
}

// getTopN returns top N items from a map, sorted by value
func getTopN(m map[string]int, n int) []kv {
	var items []kv
	for k, v := range m {
		items = append(items, kv{k, v})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})

	if len(items) > n {
		items = items[:n]
	}
	return items
}

// getStatusCodeColor returns appropriate color for status code
func getStatusCodeColor(statusCode string) aurora.Color {
	code, _ := strconv.Atoi(statusCode)
	switch {
	case code >= 200 && code < 300:
		return aurora.GreenFg
	case code >= 300 && code < 400:
		return aurora.BlueFg
	case code >= 400 && code < 500:
		return aurora.YellowFg
	case code >= 500:
		return aurora.RedFg
	default:
		return aurora.WhiteFg
	}
}
