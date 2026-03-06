package honeypot

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

// Detector tracks template match density per host and detects potential honeypots.
//
// Honeypots (e.g. on Shodan) deliberately match every nuclei template to fool scanners.
// By counting the number of distinct template matches per host, we can flag hosts that
// exhibit suspiciously high match rates.
type Detector struct {
	// threshold is the number of distinct template matches above which a host
	// is considered a likely honeypot. A value of 0 disables detection.
	threshold int

	// suppress controls whether results from flagged honeypot hosts are
	// silently dropped (true) or only warned about (false).
	suppress bool

	// hosts tracks the set of matched template IDs per normalized host.
	hosts sync.Map // map[string]*hostTracker

	// flaggedHosts stores hosts that have been flagged as honeypots.
	flaggedHosts sync.Map // map[string]bool

	// flaggedCount tracks total number of flagged hosts for summary.
	flaggedCount atomic.Int32

	// warnOnce ensures we only print one warning per host.
	warnOnce sync.Map // map[string]bool

	// warnFunc is the function called to emit warnings. Defaults to gologger
	// but can be overridden for testing.
	warnFunc func(host string, matchCount int)
}

// hostTracker holds the set of distinct template IDs that matched a host.
type hostTracker struct {
	mu          sync.Mutex
	templateIDs map[string]struct{}
}

// KnownSignatures contains patterns commonly found in honeypot responses.
// These are checked against response bodies or headers.
var KnownSignatures = []string{
	"cowrie",
	"kippo",
	"dionaea",
	"conpot",
	"glastopf",
	"elastichoney",
	"honeyd",
	"honeytrap",
	"opencanary",
	"tpotce",
	"mailoney",
	"heralding",
	"amun",
	"snare",
	"tanner",
	"gridpot",
}

// Options configures the honeypot detector.
type Options struct {
	// Threshold is the number of distinct template matches per host
	// above which the host is flagged. 0 means detection is disabled.
	Threshold int

	// Suppress controls whether flagged honeypot results are dropped (true)
	// or only warned about (false).
	Suppress bool
}

// New creates a new honeypot Detector. If threshold is 0, the detector is
// effectively a no-op.
func New(opts Options) *Detector {
	return &Detector{
		threshold: opts.Threshold,
		suppress:  opts.Suppress,
	}
}

// Enabled returns true if honeypot detection is active.
func (d *Detector) Enabled() bool {
	return d != nil && d.threshold > 0
}

// NormalizeHost extracts a canonical host identifier from a URL or host string.
// This strips scheme, path, query, fragment, and normalizes IPv6 brackets.
func NormalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// Try parsing as URL first
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil {
			host := u.Hostname()
			port := u.Port()
			if port != "" && port != "80" && port != "443" {
				return host + ":" + port
			}
			return host
		}
	}

	// Handle bare host:port or IPv6
	if strings.HasPrefix(input, "[") {
		// IPv6 with bracket notation
		if idx := strings.LastIndex(input, "]:"); idx != -1 {
			host := input[1:idx]
			port := input[idx+2:]
			if port != "80" && port != "443" {
				return host + ":" + port
			}
			return host
		}
		return strings.Trim(input, "[]")
	}

	// Simple host or host:port
	if parts := strings.SplitN(input, ":", 2); len(parts) == 2 {
		port := parts[1]
		if port != "80" && port != "443" {
			return input
		}
		return parts[0]
	}
	return input
}

// RecordMatch records that a template matched a host. It returns true if the
// host has been flagged as a honeypot (either just now or previously).
func (d *Detector) RecordMatch(host, templateID string) bool {
	if !d.Enabled() {
		return false
	}

	normalizedHost := NormalizeHost(host)
	if normalizedHost == "" {
		return false
	}

	// Fast path: already flagged
	if _, flagged := d.flaggedHosts.Load(normalizedHost); flagged {
		return true
	}

	// Get or create host tracker
	trackerI, _ := d.hosts.LoadOrStore(normalizedHost, &hostTracker{
		templateIDs: make(map[string]struct{}),
	})
	tracker := trackerI.(*hostTracker)

	tracker.mu.Lock()
	tracker.templateIDs[templateID] = struct{}{}
	count := len(tracker.templateIDs)
	tracker.mu.Unlock()

	if count >= d.threshold {
		// Flag as honeypot
		if _, loaded := d.flaggedHosts.LoadOrStore(normalizedHost, true); !loaded {
			d.flaggedCount.Add(1)
			d.emitWarning(normalizedHost, count)
		}
		return true
	}
	return false
}

// IsFlagged returns true if the given host has been flagged as a honeypot.
func (d *Detector) IsFlagged(host string) bool {
	if !d.Enabled() {
		return false
	}
	normalizedHost := NormalizeHost(host)
	_, flagged := d.flaggedHosts.Load(normalizedHost)
	return flagged
}

// ShouldSuppress returns true if results for this host should be dropped.
func (d *Detector) ShouldSuppress(host string) bool {
	if !d.Enabled() || !d.suppress {
		return false
	}
	return d.IsFlagged(host)
}

// MatchCount returns the number of distinct template matches for a host.
func (d *Detector) MatchCount(host string) int {
	if !d.Enabled() {
		return 0
	}
	normalizedHost := NormalizeHost(host)
	trackerI, ok := d.hosts.Load(normalizedHost)
	if !ok {
		return 0
	}
	tracker := trackerI.(*hostTracker)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return len(tracker.templateIDs)
}

// FlaggedHosts returns a list of all hosts flagged as honeypots along with
// their match counts.
func (d *Detector) FlaggedHosts() []FlaggedHost {
	if !d.Enabled() {
		return nil
	}
	var results []FlaggedHost
	d.flaggedHosts.Range(func(key, _ any) bool {
		host := key.(string)
		count := d.MatchCount(host)
		results = append(results, FlaggedHost{
			Host:       host,
			MatchCount: count,
		})
		return true
	})
	return results
}

// FlaggedCount returns the total number of flagged honeypot hosts.
func (d *Detector) FlaggedCount() int {
	if d == nil {
		return 0
	}
	return int(d.flaggedCount.Load())
}

// FlaggedHost stores information about a flagged honeypot host.
type FlaggedHost struct {
	Host       string
	MatchCount int
}

// ContainsKnownSignature checks whether a response body or header contains
// known honeypot software signatures.
func ContainsKnownSignature(data string) (bool, string) {
	lower := strings.ToLower(data)
	for _, sig := range KnownSignatures {
		if strings.Contains(lower, sig) {
			return true, sig
		}
	}
	return false, ""
}

// SetWarnFunc overrides the warning function (useful for testing).
func (d *Detector) SetWarnFunc(fn func(host string, matchCount int)) {
	d.warnFunc = fn
}

// emitWarning prints a one-time warning when a host is flagged.
func (d *Detector) emitWarning(host string, matchCount int) {
	if _, loaded := d.warnOnce.LoadOrStore(host, true); loaded {
		return
	}
	if d.warnFunc != nil {
		d.warnFunc(host, matchCount)
		return
	}
	// Default: print to stderr via fmt (gologger is imported by the integration layer)
	fmt.Printf("[HONEYPOT] %s flagged as potential honeypot (%d template matches exceeded threshold)\n", host, matchCount)
}
