// Package httpcache provides RFC 9111 compliant HTTP response caching for nuclei.
// It wraps http.RoundTripper to cache responses based on standard HTTP caching headers.
package httpcache

import (
	"bufio"
	"bytes"
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
// The cache is stored under the nuclei cache directory (httpcache/).
// If leveldb initialization fails, falls back to in-memory cache.
func GetCache() httpcache.Cache {
	cacheOnce.Do(func() {
		cacheDir := filepath.Join(config.DefaultConfig.GetCacheDir(), "httpcache")
		disk, err := leveldbcache.New(cacheDir)
		if err != nil {
			gologger.Warning().Msgf("HTTP cache: could not open %q, using memory: %s", cacheDir, err)
			cache = &statusFilterCache{inner: httpcache.NewMemoryCache()}
			return
		}
		gologger.Verbose().Msgf("HTTP cache initialized at %q", cacheDir)
		cache = &statusFilterCache{inner: disk}
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

// shouldCache is passed to the library hook. That hook only runs for status
// codes outside the built-in cacheable list, so 301/404/501 still need
// statusFilterCache to keep them off disk.
func shouldCache(resp *http.Response) bool {
	return isCacheableStatus(resp.StatusCode)
}

func isCacheableStatus(code int) bool {
	return code >= 200 && code < 300
}

// statusFilterCache drops non-2xx entries. sandrolain/httpcache v1.4.0 stores
// 301/404/405/410/414/501 without calling ShouldCache.
type statusFilterCache struct {
	inner httpcache.Cache
}

func (c *statusFilterCache) Get(key string) ([]byte, bool) {
	data, ok := c.inner.Get(key)
	if !ok {
		return nil, false
	}
	if !storedResponseIs2xx(data) {
		c.inner.Delete(key)
		return nil, false
	}
	return data, true
}

func (c *statusFilterCache) Set(key string, responseBytes []byte) {
	if !storedResponseIs2xx(responseBytes) {
		return
	}
	c.inner.Set(key, responseBytes)
}

func (c *statusFilterCache) Delete(key string) {
	c.inner.Delete(key)
}

func storedResponseIs2xx(data []byte) bool {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return isCacheableStatus(resp.StatusCode)
}
