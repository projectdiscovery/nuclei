package frequency

import (
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bluele/gcache"
	"github.com/projectdiscovery/gologger"
)

// Tracker implements a frequency tracker for a given input
// which is used to determine uninteresting input parameters
// which are not that interesting from fuzzing perspective for a template
// and target combination.
//
// This is used to reduce the number of requests made during fuzzing
// for parameters that are less likely to give results for a rule.
type Tracker struct {
	frequencies             gcache.Cache
	paramOccurenceThreshold int

	isDebug bool
}

const (
	DefaultMaxTrackCount           = 10000
	DefaultParamOccurenceThreshold = 10
)

type cacheItem struct {
	errors atomic.Int32
	sync.Once
}

// New creates a new frequency tracker with a given maximum
// number of params to track in LRU fashion with a max error threshold
func New(maxTrackCount, paramOccurenceThreshold int) *Tracker {
	gc := gcache.New(maxTrackCount).ARC().Build()

	var isDebug bool
	if os.Getenv("FREQ_DEBUG") != "" {
		isDebug = true
	}
	return &Tracker{
		isDebug:                 isDebug,
		frequencies:             gc,
		paramOccurenceThreshold: paramOccurenceThreshold,
	}
}

func (t *Tracker) Close() {
	t.frequencies.Purge()
}

// MarkParameter marks a parameter as frequently occuring once.
//
// The logic requires a parameter to be marked as frequently occuring
// multiple times before it's considered as frequently occuring.
func (t *Tracker) MarkParameter(parameter, target, template string) {
	normalizedTarget := normalizeTarget(target)
	key := getFrequencyKey(parameter, normalizedTarget, template)

	if t.isDebug {
		gologger.Verbose().Msgf("[%s] Marking %s as found uninteresting", template, key)
	}

	existingCacheItem, err := t.frequencies.GetIFPresent(key)
	if err != nil || existingCacheItem == nil {
		newItem := &cacheItem{errors: atomic.Int32{}}
		newItem.errors.Store(1)
		_ = t.frequencies.Set(key, newItem)
		return
	}
	existingCacheItemValue := existingCacheItem.(*cacheItem)
	existingCacheItemValue.errors.Add(1)

	_ = t.frequencies.Set(key, existingCacheItemValue)
}

// IsParameterFrequent checks if a parameter is frequently occuring
// in the input with no much results.
func (t *Tracker) IsParameterFrequent(parameter, target, template string) bool {
	normalizedTarget := normalizeTarget(target)
	key := getFrequencyKey(parameter, normalizedTarget, template)

	if t.isDebug {
		gologger.Verbose().Msgf("[%s] Checking if %s is frequently found uninteresting", template, key)
	}

	existingCacheItem, err := t.frequencies.GetIFPresent(key)
	if err != nil {
		return false
	}
	existingCacheItemValue := existingCacheItem.(*cacheItem)

	if existingCacheItemValue.errors.Load() >= int32(t.paramOccurenceThreshold) {
		existingCacheItemValue.Do(func() {
			gologger.Verbose().Msgf("[%s] Skipped %s from parameter for %s as found uninteresting %d times", template, parameter, target, existingCacheItemValue.errors.Load())
		})
		return true
	}
	return false
}

// UnmarkParameter unmarks a parameter as frequently occuring. This carries
// more weight and resets the frequency counter for the parameter causing
// it to be checked again. This is done when results are found.
func (t *Tracker) UnmarkParameter(parameter, target, template string) {
	normalizedTarget := normalizeTarget(target)
	key := getFrequencyKey(parameter, normalizedTarget, template)

	if t.isDebug {
		gologger.Verbose().Msgf("[%s] Unmarking %s as frequently found uninteresting", template, key)
	}

	_ = t.frequencies.Remove(key)
}

func getFrequencyKey(parameter, target, template string) string {
	var sb strings.Builder
	sb.WriteString(target)
	sb.WriteString(":")
	sb.WriteString(template)
	sb.WriteString(":")
	sb.WriteString(parameter)
	str := sb.String()
	return str
}

func normalizeTarget(value string) string {
	finalValue := value
	if strings.HasPrefix(value, "http") {
		if parsed, err := url.Parse(value); err == nil {
			hostname := parsed.Host
			finalPort := parsed.Port()
			if finalPort == "" {
				if parsed.Scheme == "https" {
					finalPort = "443"
				} else {
					finalPort = "80"
				}
				hostname = net.JoinHostPort(parsed.Host, finalPort)
			}
			finalValue = hostname
		}
	}
	return finalValue
}
