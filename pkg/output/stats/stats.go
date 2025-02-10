// Package stats provides a stats tracker for tracking Status Codes,
// Errors & WAF detection events.
//
// It is wrapped and called by output.Writer interface.
package stats

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"sync/atomic"

	"github.com/logrusorgru/aurora"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Tracker is a stats tracker instance for nuclei scans
type Tracker struct {
	// counters for various stats
	statusCodes *mapsutil.SyncLockMap[string, *atomic.Int32]
	errorCodes  *mapsutil.SyncLockMap[string, *atomic.Int32]
	wafDetected *mapsutil.SyncLockMap[string, *atomic.Int32]

	// internal stuff
	wafDetector *wafDetector
}

// NewTracker creates a new Tracker instance.
func NewTracker() *Tracker {
	return &Tracker{
		statusCodes: mapsutil.NewSyncLockMap[string, *atomic.Int32](),
		errorCodes:  mapsutil.NewSyncLockMap[string, *atomic.Int32](),
		wafDetected: mapsutil.NewSyncLockMap[string, *atomic.Int32](),
		wafDetector: newWafDetector(),
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
	waf, ok := t.wafDetector.DetectWAF(httpResponse)
	if !ok {
		return
	}

	t.incrementCounter(t.wafDetected, waf)
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
		waf, ok := t.wafDetector.wafs[k]
		if !ok {
			return nil
		}
		stats.WAFStats[waf.Name] = int(v.Load())
		return nil
	})
	return stats
}

type wafDetector struct {
	wafs       map[string]waf
	regexCache map[string]*regexp.Regexp
}

// waf represents a web application firewall definition
type waf struct {
	Company string `json:"company"`
	Name    string `json:"name"`
	Regex   string `json:"regex"`
}

// wafData represents the root JSON structure
type wafData struct {
	WAFs map[string]waf `json:"wafs"`
}

//go:embed regexes.json
var wafContentRegexes string

func newWafDetector() *wafDetector {
	var data wafData
	if err := json.Unmarshal([]byte(wafContentRegexes), &data); err != nil {
		panic("could not unmarshal waf content regexes: " + err.Error())
	}

	store := &wafDetector{
		wafs:       data.WAFs,
		regexCache: make(map[string]*regexp.Regexp),
	}

	for id, waf := range store.wafs {
		if waf.Regex == "" {
			continue
		}
		store.regexCache[id] = regexp.MustCompile(waf.Regex)
	}
	return store
}

func (d *wafDetector) DetectWAF(content string) (string, bool) {
	for id, regex := range d.regexCache {
		if regex.MatchString(content) {
			return id, true
		}
	}
	return "", false
}

// DisplayTopStats prints the most relevant statistics for CLI
func (t *Tracker) DisplayTopStats(noColor bool) {
	stats := t.GetStats()

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
