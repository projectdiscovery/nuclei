package hosterrorscache

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/nucleierr"
	"github.com/projectdiscovery/utils/errkit"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// CacheInterface defines the signature of the hosterrorscache so that
// users of Nuclei as embedded lib may implement their own cache
type CacheInterface interface {
	SetVerbose(verbose bool)                                                  // log verbosely
	Close()                                                                   // close the cache
	Check(protoType string, ctx *contextargs.Context) bool                    // return true if the host should be skipped
	Remove(ctx *contextargs.Context)                                          // remove a host from the cache
	MarkFailed(protoType string, ctx *contextargs.Context, err error)         // record a failure (and cause) for the host
	MarkFailedOrRemove(protoType string, ctx *contextargs.Context, err error) // record a failure (and cause) for the host or remove it
}

var (
	_ CacheInterface = (*Cache)(nil)
)

// Cache is a cache for host based errors. It allows skipping
// certain hosts based on an error threshold.
//
// It uses an LRU cache internally for skipping unresponsive hosts
// that remain so for a duration.
type Cache struct {
	MaxHostError  int
	verbose       bool
	failedTargets gcache.Cache[string, *cacheItem]
	TrackError    []string
}

type cacheItem struct {
	sync.Once
	errors         atomic.Int32
	isPermanentErr bool
	cause          error // optional cause
	mu             sync.Mutex
}

const DefaultMaxHostsCount = 10000

// New returns a new host max errors cache
func New(maxHostError, maxHostsCount int, trackError []string) *Cache {
	gc := gcache.New[string, *cacheItem](maxHostsCount).ARC().Build()

	return &Cache{
		failedTargets: gc,
		MaxHostError:  maxHostError,
		TrackError:    trackError,
	}
}

// SetVerbose sets the cache to log at verbose level
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// Close closes the host errors cache
func (c *Cache) Close() {
	if config.DefaultConfig.IsDebugArgEnabled(config.DebugArgHostErrorStats) {
		items := c.failedTargets.GetALL(false)
		for k, val := range items {
			gologger.Info().Label("MaxHostErrorStats").Msgf("Host: %s, Errors: %d", k, val.errors.Load())
		}
	}
	c.failedTargets.Purge()
}

// NormalizeCacheValue processes the input value and returns a normalized cache
// value.
func (c *Cache) NormalizeCacheValue(value string) string {
	var normalizedValue string = value

	u, err := url.ParseRequestURI(value)
	if err != nil || u.Host == "" {
		u, err2 := url.ParseRequestURI("https://" + value)
		if err2 != nil {
			return normalizedValue
		}

		normalizedValue = u.Host
	} else {
		port := u.Port()
		if port == "" {
			switch u.Scheme {
			case "https":
				normalizedValue = net.JoinHostPort(u.Host, "443")
			case "http":
				normalizedValue = net.JoinHostPort(u.Host, "80")
			}
		} else {
			normalizedValue = u.Host
		}
	}

	return normalizedValue
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
func (c *Cache) Check(protoType string, ctx *contextargs.Context) bool {
	finalValue := c.GetKeyFromContext(ctx, nil)

	cache, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil {
		return false
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.isPermanentErr {
		// skipping permanent errors is expected so verbose instead of info
		gologger.Verbose().Msgf("Skipped %s from target list as found unresponsive permanently: %s", finalValue, cache.cause)
		return true
	}

	if cache.errors.Load() >= int32(c.MaxHostError) {
		cache.Do(func() {
			gologger.Info().Msgf("Skipped %s from target list as found unresponsive %d times", finalValue, cache.errors.Load())
		})
		return true
	}

	return false
}

// Remove removes a host from the cache
func (c *Cache) Remove(ctx *contextargs.Context) {
	key := c.GetKeyFromContext(ctx, nil)
	_ = c.failedTargets.Remove(key) // remove even the cache is not present
}

// MarkFailed marks a host as failed previously
//
// Deprecated: Use MarkFailedOrRemove instead.
func (c *Cache) MarkFailed(protoType string, ctx *contextargs.Context, err error) {
	if err == nil {
		return
	}

	c.MarkFailedOrRemove(protoType, ctx, err)
}

// MarkFailedOrRemove marks a host as failed previously or removes it
func (c *Cache) MarkFailedOrRemove(protoType string, ctx *contextargs.Context, err error) {
	if err != nil && !c.checkError(protoType, err) {
		return
	}

	if err == nil {
		// Remove the host from cache
		//
		// NOTE(dwisiswant0): The decision was made to completely remove the
		// cached entry for the host instead of simply decrementing the error
		// count (using `(atomic.Int32).Swap` to update the value to `N-1`).
		// This approach was chosen because the error handling logic operates
		// concurrently, and decrementing the count could lead to UB (unexpected
		// behavior) even when the error is `nil`.
		//
		// To clarify, consider the following scenario where the error
		// encountered does NOT belong to the permanent network error category
		// (`errkit.ErrKindNetworkPermanent`):
		//
		// 1. Iteration 1: A timeout error occurs, and the error count for the
		//    host is incremented.
		// 2. Iteration 2: Another timeout error is encountered, leading to
		//    another increment in the host's error count.
		// 3. Iteration 3: A third timeout error happens, which increments the
		//    error count further. At this point, the host is flagged as
		//    unresponsive.
		// 4. Iteration 4: The host becomes reachable (no error or a transient
		//    issue resolved). Instead of performing a no-op and leaving the
		//    host in the cache, the host entry is removed entirely to reset its
		//    state.
		// 5. Iteration 5: A subsequent timeout error occurs after the host was
		//    removed and re-added to the cache. The error count is reset and
		//    starts from 1 again.
		//
		// This removal strategy ensures the cache is updated dynamically to
		// reflect the current state of the host without persisting stale or
		// irrelevant error counts that could interfere with future error
		// handling and tracking logic.
		c.Remove(ctx)

		return
	}

	cacheKey := c.GetKeyFromContext(ctx, err)
	cache, cacheErr := c.failedTargets.GetIFPresent(cacheKey)
	if errors.Is(cacheErr, gcache.KeyNotFoundError) {
		cache = &cacheItem{errors: atomic.Int32{}}
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if errkit.IsKind(err, errkit.ErrKindNetworkPermanent) {
		cache.isPermanentErr = true
	}

	cache.cause = err
	cache.errors.Add(1)

	_ = c.failedTargets.Set(cacheKey, cache)
}

// GetKeyFromContext returns the key for the cache from the context
func (c *Cache) GetKeyFromContext(ctx *contextargs.Context, err error) string {
	// Note:
	// ideally any changes made to remote addr in template like {{Hostname}}:81 etc
	// should be reflected in contextargs but it is not yet reflected in some cases
	// and needs refactor of ScanContext + ContextArgs to achieve that
	// i.e why we use real address from error if present
	address := ctx.MetaInput.Address()
	// get address override from error
	if err != nil {
		tmp := errkit.GetAttrValue(err, "address")
		if tmp.Any() != nil {
			address = tmp.String()
		}
	}
	finalValue := c.NormalizeCacheValue(address)
	return finalValue
}

var reCheckError = regexp.MustCompile(`(no address found for host|could not resolve host|connection refused|connection reset by peer|could not connect to any address found for host|timeout awaiting response headers)`)

// checkError checks if an error represents a type that should be
// added to the host skipping table.
// it first parses error and extracts the cause and checks for blacklisted
// or common errors that should be skipped
func (c *Cache) checkError(protoType string, err error) bool {
	if err == nil {
		return false
	}
	if protoType != "http" {
		return false
	}
	kind := errkit.GetErrorKind(err, nucleierr.ErrTemplateLogic)
	switch kind {
	case nucleierr.ErrTemplateLogic:
		// these are errors that are not related to the target
		// and are due to template logic
		return false
	case errkit.ErrKindNetworkTemporary:
		// these should not be counted as host errors
		return false
	case errkit.ErrKindNetworkPermanent:
		// these should be counted as host errors
		return true
	case errkit.ErrKindDeadline:
		// these should not be counted as host errors
		return false
	default:
		// parse error for further processing
		errX := errkit.FromError(err)
		tmp := errX.Cause()
		cause := tmp.Error()
		if stringsutil.ContainsAll(cause, "ReadStatusLine:", "read: connection reset by peer") {
			// this is a FP and should not be counted as a host error
			// because server closes connection when it reads corrupted bytes which we send via rawhttp
			return false
		}
		if strings.HasPrefix(cause, "ReadStatusLine:") {
			// error is present in last part when using rawhttp
			// this will be fixed once errkit is used everywhere
			lastIndex := strings.LastIndex(cause, ":")
			if lastIndex == -1 {
				lastIndex = 0
			}
			if lastIndex >= len(cause)-1 {
				lastIndex = 0
			}
			cause = cause[lastIndex+1:]
		}
		for _, msg := range c.TrackError {
			if strings.Contains(cause, msg) {
				return true
			}
		}
		return reCheckError.MatchString(cause)
	}
}
