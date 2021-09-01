package hosterrorscache

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/bluele/gcache"
	"github.com/projectdiscovery/gologger"
)

// Cache is a cache for host based errors. It allows skipping
// certain hosts based on an error threshold.
//
// It uses an LRU cache internally for skipping unresponsive hosts
// that remain so for a duration.
type Cache struct {
	MaxHostError int
	verbose       bool
	failedTargets gcache.Cache
}

const DefaultMaxHostsCount = 10000

// New returns a new host max errors cache
func New(MaxHostError, maxHostsCount int) *Cache {
	gc := gcache.New(maxHostsCount).
		ARC().
		Build()
	return &Cache{failedTargets: gc, MaxHostError: MaxHostError}
}

// SetVerbose sets the cache to log at verbose level
func (c *Cache) SetVerbose(verbose bool) *Cache {
	c.verbose = verbose
	return c
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
//var ErrUnresponsiveHost = errors.New("skipping as host is unresponsive")

// Check returns true if a host should be skipped as it has been
// unresponsive for a certain number of times.
//
// The value can be many formats -
//   - URL: https?:// type
//   - Host:port type
//   - host type
func (c *Cache) Check(value string) bool {
	finalValue := c.normalizeCacheValue(value)
	if !c.failedTargets.Has(finalValue) {
		return false
	}

	numberOfErrors, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil {
		return false
	}
	numberOfErrorsValue := numberOfErrors.(int)

	if numberOfErrors == -1 {
		return true
	}
	if numberOfErrorsValue >= c.MaxHostError {
		_ = c.failedTargets.Set(finalValue, -1)
		if c.verbose {
			gologger.Verbose().Msgf("Skipping %s as previously unresponsive %d times", finalValue, numberOfErrorsValue)
		}
		return true
	}
	return false
}

// MarkFailed marks a host as failed previously
func (c *Cache) MarkFailed(value string) {
	finalValue := c.normalizeCacheValue(value)
	if !c.failedTargets.Has(finalValue) {
		_ = c.failedTargets.Set(finalValue, 1)
		return
	}

	numberOfErrors, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil || numberOfErrors == nil {
		_ = c.failedTargets.Set(finalValue, 1)
		return
	}
	numberOfErrorsValue := numberOfErrors.(int)

	_ = c.failedTargets.Set(finalValue, numberOfErrorsValue+1)
}

var checkErrorRegexp = regexp.MustCompile(`(no address found for host|Client\.Timeout exceeded while awaiting headers|could not resolve host)`)

// CheckError checks if an error represents a type that should be
// added to the host skipping table.
func (c *Cache) CheckError(err error) bool {
	errString := err.Error()
	return checkErrorRegexp.MatchString(errString)
}
