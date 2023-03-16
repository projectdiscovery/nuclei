package atomcache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/karlseguin/ccache"
)

type Cache struct {
	*ccache.Cache
	Closed atomic.Bool
	mu     sync.RWMutex
}

func NewWithCache(c *ccache.Cache) *Cache {
	return &Cache{Cache: c}
}

func (c *Cache) Get(key string) *ccache.Item {
	if c.Closed.Load() {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Cache.Get(key)
}

func (c *Cache) Set(key string, value interface{}, duration time.Duration) {
	if c.Closed.Load() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Cache.Set(key, value, duration)
}

func (c *Cache) Delete(key string) bool {
	if c.Closed.Load() {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.Cache.Delete(key)
}

func (c *Cache) Stop() {
	if c.Closed.Load() {
		return
	}
	c.Closed.Store(true)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.Cache.Stop()
}
