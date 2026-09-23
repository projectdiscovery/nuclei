// Package httpcache provides RFC 9111 compliant HTTP response caching for nuclei.
// It wraps http.RoundTripper to cache responses based on standard HTTP caching headers.
package httpcache

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/sandrolain/httpcache"
	"github.com/sandrolain/httpcache/leveldbcache"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const defaultMaxCacheBytes = 256 << 20 // 256 MiB

var (
	cacheMu       sync.Mutex
	cache         httpcache.Cache
	diskDB        *leveldb.DB
	maxCacheBytes int64 = defaultMaxCacheBytes
)

// GetCache returns the shared cache, opening LevelDB on first use.
// After Close, the next call opens a new handle.
func GetCache() httpcache.Cache {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cache != nil {
		return cache
	}

	cacheDir := filepath.Join(config.DefaultConfig.GetCacheDir(), "httpcache")
	opened, db, err := openDiskCache(cacheDir, maxCacheBytes)
	if err != nil {
		gologger.Warning().Msgf("HTTP cache: could not open %q, using memory: %s", cacheDir, err)
		cache = newBoundedCache(httpcache.NewMemoryCache(), "", maxCacheBytes)
		return cache
	}
	gologger.Verbose().Msgf("HTTP cache initialized at %q (max %d bytes)", cacheDir, maxCacheBytes)
	diskDB = db
	cache = opened
	return cache
}

// Close releases the LevelDB handle. Safe if the cache was never opened or
// is using the memory fallback. The next GetCache call reopens it.
func Close() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if diskDB != nil {
		if err := diskDB.Close(); err != nil {
			gologger.Warning().Msgf("HTTP cache: close: %s", err)
		}
		diskDB = nil
	}
	cache = nil
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

func openDiskCache(dir string, maxBytes int64) (httpcache.Cache, *leveldb.DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create cache dir: %w", err)
	}

	db, err := leveldb.OpenFile(dir, &opt.Options{
		WriteBuffer:         1 << 20,
		CompactionTableSize: 2 << 20,
	})
	if err != nil {
		return nil, nil, err
	}

	return newBoundedCache(leveldbcache.NewWithDB(db), dir, maxBytes), db, nil
}

func shouldCache(resp *http.Response) bool {
	return isCacheableStatus(resp.StatusCode)
}

func isCacheableStatus(code int) bool {
	return code >= 200 && code < 300
}

func newBoundedCache(inner httpcache.Cache, dir string, maxBytes int64) *statusFilterCache {
	return &statusFilterCache{
		inner:    inner,
		dir:      dir,
		maxBytes: maxBytes,
	}
}

// statusFilterCache drops non-2xx entries. sandrolain/httpcache v1.4.0 stores
// 301/404/405/410/414/501 without calling ShouldCache.
// When dir is set, Set is skipped once the LevelDB directory reaches maxBytes.
type statusFilterCache struct {
	inner      httpcache.Cache
	dir        string
	maxBytes   int64
	setCount   atomic.Uint32
	fullWarned atomic.Bool
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
	if c.maxBytes > 0 && c.overBudget(len(responseBytes)) {
		if c.fullWarned.CompareAndSwap(false, true) {
			gologger.Warning().Msgf("HTTP cache: at %d byte cap, not storing more responses", c.maxBytes)
		}
		return
	}
	c.inner.Set(key, responseBytes)
}

func (c *statusFilterCache) Delete(key string) {
	c.inner.Delete(key)
}

func (c *statusFilterCache) overBudget(incoming int) bool {
	if c.dir == "" {
		return false
	}
	// Directory walk is not free; sample every 32 writes after the first.
	n := c.setCount.Add(1)
	if n > 1 && n%32 != 0 {
		return false
	}
	return dirSize(c.dir)+int64(incoming) >= c.maxBytes
}

func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

func storedResponseIs2xx(data []byte) bool {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return isCacheableStatus(resp.StatusCode)
}
