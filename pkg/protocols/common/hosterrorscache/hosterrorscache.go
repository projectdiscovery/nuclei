package hosterrorscache

import (
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
	SetVerbose(verbose bool)                        // log verbosely
	Close()                                         // close the cache
	Check(ctx *contextargs.Context) bool            // return true if the host should be skipped
	MarkFailed(ctx *contextargs.Context, err error) // record a failure (and cause) for the host
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
}

const DefaultMaxHostsCount = 10000

// New returns a new host max errors cache
func New(maxHostError, maxHostsCount int, trackError []string) *Cache {
	gc := gcache.New[string, *cacheItem](maxHostsCount).
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
	if config.DefaultConfig.IsDebugArgEnabled(config.DebugArgHostErrorStats) {
		items := c.failedTargets.GetALL(false)
		for k, val := range items {
			gologger.Info().Label("MaxHostErrorStats").Msgf("Host: %s, Errors: %d", k, val.errors.Load())
		}
	}
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
func (c *Cache) Check(ctx *contextargs.Context) bool {
	finalValue := c.GetKeyFromContext(ctx, nil)

	existingCacheItem, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil {
		return false
	}
	if existingCacheItem.isPermanentErr {
		// skipping permanent errors is expected so verbose instead of info
		gologger.Verbose().Msgf("Skipped %s from target list as found unresponsive permanently: %s", finalValue, existingCacheItem.cause)
		return true
	}

	if existingCacheItem.errors.Load() >= int32(c.MaxHostError) {
		existingCacheItem.Do(func() {
			gologger.Info().Msgf("Skipped %s from target list as found unresponsive %d times", finalValue, existingCacheItem.errors.Load())
		})
		return true
	}
	return false
}

// MarkFailed marks a host as failed previously
func (c *Cache) MarkFailed(ctx *contextargs.Context, err error) {
	if !c.checkError(err) {
		return
	}
	finalValue := c.GetKeyFromContext(ctx, err)
	existingCacheItem, err := c.failedTargets.GetIFPresent(finalValue)
	if err != nil || existingCacheItem == nil {
		newItem := &cacheItem{errors: atomic.Int32{}}
		newItem.errors.Store(1)
		if errkit.IsKind(err, errkit.ErrKindNetworkPermanent) {
			// skip this address altogether
			// permanent errors are always permanent hence this is created once
			// and never updated so no need to synchronize
			newItem.isPermanentErr = true
			newItem.cause = err
		}
		_ = c.failedTargets.Set(finalValue, newItem)
		return
	}
	existingCacheItem.errors.Add(1)
	_ = c.failedTargets.Set(finalValue, existingCacheItem)
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
	finalValue := c.normalizeCacheValue(address)
	return finalValue
}

var reCheckError = regexp.MustCompile(`(no address found for host|could not resolve host|connection refused|connection reset by peer|could not connect to any address found for host|timeout awaiting response headers)`)

// checkError checks if an error represents a type that should be
// added to the host skipping table.
// it first parses error and extracts the cause and checks for blacklisted
// or common errors that should be skipped
func (c *Cache) checkError(err error) bool {
	if err == nil {
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
