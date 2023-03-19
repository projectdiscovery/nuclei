package hosterrorscache

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bluele/gcache"
	"github.com/projectdiscovery/gologger"
)

// CacheInterface defines the signature of the hosterrorscache so that
// users of Nuclei as embedded lib may implement their own cache
type CacheInterface interface {
	SetVerbose(verbose bool)            // log verbosely
	Close()                             // close the cache
	Check(value string) bool            // return true if the host should be skipped
	MarkFailed(value string, err error) // record a failure (and cause) for the host
}

// Cache is a cache for host based errors. It allows skipping
// certain hosts based on an error threshold.
//
// It uses an LRU cache internally for skipping unresponsive hosts
// that remain so for a duration.
type Cache struct {
	MaxHostError  int
	verbose       bool
	failedTargets gcache.Cache
	TrackError    []string
}

type cacheItem struct {
	errors atomic.Int32
	sync.Once
}

const DefaultMaxHostsCount = 10000

// New returns a new host max errors cache
func New(maxHostError, maxHostsCount int, trackError []string) *Cache {
	gc := gcache.New(maxHostsCount).
		ARC().
		Build()
	return &Cache{failedTargets: gc, MaxHostError: maxHostError, TrackError: trackError}
}

// SetVerbose sets the cache to log at verbose level
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// Close closes the host errors cache
func (c *Cache) Close() {
	c.failedTargets.Purge()
}

func (c *Cache) normalizeCacheValue(value string) string {
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

// ErrUnresponsiveHost is returned when a host is unresponsive
// var ErrUnresponsiveHost = errors.New("skipping as host is unresponsive")

// Check returns true if a host should be skipped as it has been
// unresponsive for a certain number of times.
//
// The value can be many formats -
//   - URL: https?:// type
//   - Host:port type
//   - host type
func (c *Cache) Check(value string) bool {
	finalValue := c.normalizeCacheValue(value)

	existingCacheItem, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil {
		return false
	}
	existingCacheItemValue := existingCacheItem.(*cacheItem)

	if existingCacheItemValue.errors.Load() >= int32(c.MaxHostError) {
		existingCacheItemValue.Do(func() {
			gologger.Info().Msgf("Skipped %s from target list as found unresponsive %d times", finalValue, existingCacheItemValue.errors.Load())
		})
		return true
	}
	return false
}

// MarkFailed marks a host as failed previously
func (c *Cache) MarkFailed(value string, err error) {
	if !c.checkError(err) {
		return
	}
	finalValue := c.normalizeCacheValue(value)
	existingCacheItem, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil || existingCacheItem == nil {
		newItem := &cacheItem{errors: atomic.Int32{}}
		newItem.errors.Store(1)
		_ = c.failedTargets.Set(finalValue, newItem)
		return
	}
	existingCacheItemValue := existingCacheItem.(*cacheItem)
	existingCacheItemValue.errors.Add(1)
	_ = c.failedTargets.Set(finalValue, existingCacheItemValue)
}

var reCheckError = regexp.MustCompile(`(no address found for host|Client\.Timeout exceeded while awaiting headers|could not resolve host|connection refused)`)

// checkError checks if an error represents a type that should be
// added to the host skipping table.
func (c *Cache) checkError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()
	for _, msg := range c.TrackError {
		if strings.Contains(errString, msg) {
			return true
		}
	}
	return reCheckError.MatchString(errString)
}
