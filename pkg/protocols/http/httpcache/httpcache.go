// Package httpcache provides RFC 9111 compliant HTTP response caching for nuclei.
// It wraps http.RoundTripper to cache responses based on standard HTTP caching headers.
package httpcache

import (
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/sandrolain/httpcache"
	"github.com/sandrolain/httpcache/leveldbcache"
)

var (
	// cache is the shared cache instance
	cache     httpcache.Cache
	cacheOnce sync.Once
)

// GetCache returns the singleton cache instance, creating it if necessary.
//
// The cache is stored in the user's cache directory (~/.cache/nuclei/httpcache/).
// If leveldb initialization fails, falls back to in-memory cache.
func GetCache() httpcache.Cache {
	cacheOnce.Do(func() {
		cacheDir := filepath.Join(config.DefaultConfig.GetCacheDir(), "httpcache")
		var err error
		cache, err = leveldbcache.New(cacheDir)
		if err != nil {
			cache = httpcache.NewMemoryCache()
		} else {
			gologger.Verbose().Msgf("HTTP cache initialized at %q", cacheDir)
		}
	})

	return cache
}

// NewTransportWrapper returns a function that wraps an [http.RoundTripper] with
// caching.
//
// This is designed to be used with retryablehttp's WrapTransport option.
func NewTransportWrapper() func(http.RoundTripper) http.RoundTripper {
	c := GetCache()

	return func(rt http.RoundTripper) http.RoundTripper {
		transport := &httpcache.Transport{
			Transport:                 rt,
			Cache:                     c,
			MarkCachedResponses:       false,
			SkipServerErrorsFromCache: true,
			AsyncRevalidateTimeout:    10 * time.Second,
			IsPublicCache:             false,
			EnableVarySeparation:      true,
			ShouldCache:               shouldCache,
			CacheKeyHeaders: []string{
				"Authorization",
				"Cookie",
				"Accept-Encoding",
				"Accept-Language",
				"Accept",
				"Origin",
			},
			DisableWarningHeader: true,
		}
		return transport
	}
}

// shouldCache determines whether a response should be cached.
// Only caches successful 2XX responses.
func shouldCache(resp *http.Response) bool {
	// Only cache successful responses (2XX status codes)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
