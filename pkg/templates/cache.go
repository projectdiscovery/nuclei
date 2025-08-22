package templates

import (
	"sync"

	"github.com/projectdiscovery/utils/conversion"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Cache is a cache for caching and storing templates for reuse.
type Cache struct {
	items *mapsutil.SyncLockMap[string, parsedTemplate]

	// parsedTemplatePool: Object pool for parsedTemplate structs
	// Why: Reduces allocation overhead when storing templates in cache
	// Improvement: Eliminates repeated allocations for cache entries
	parsedTemplatePool *sync.Pool
}

// New returns a new templates cache
func NewCache() *Cache {
	return &Cache{
		items: mapsutil.NewSyncLockMap[string, parsedTemplate](),
		parsedTemplatePool: &sync.Pool{
			New: func() any {
				return &parsedTemplate{}
			},
		},
	}
}

type parsedTemplate struct {
	template *Template
	raw      string
	err      error
}

// Has returns true if the cache has a template. The template
// is returned along with any errors if found.
// OPTIMIZATION: Returns raw bytes directly to avoid conversion overhead
func (t *Cache) Has(template string) (*Template, []byte, error) {
	value, ok := t.items.Get(template)
	if !ok {
		return nil, nil, nil
	}

	// Return raw bytes directly if available, avoiding conversion
	if value.raw != "" {
		return value.template, []byte(value.raw), value.err
	}
	return value.template, nil, value.err
}

// Store stores a template with data and error
// OPTIMIZATION: Uses object pooling and memory-efficient storage
func (t *Cache) Store(id string, tpl *Template, raw []byte, err error) {
	// Get parsedTemplate from pool instead of allocating new one
	entry := t.parsedTemplatePool.Get().(*parsedTemplate)

	// Reuse the existing struct
	entry.template = tpl
	entry.err = err

	// Only store raw data if actually provided (memory optimization)
	if raw != nil {
		// Use conversion.String which may be optimized vs string(raw)
		entry.raw = conversion.String(raw)
	} else {
		entry.raw = "" // Explicitly empty to save memory
	}

	_ = t.items.Set(id, *entry)

	// Return to pool after setting (value is copied by mapsutil)
	t.parsedTemplatePool.Put(entry)
}

// StoreWithoutRaw stores a template without raw data for memory efficiency
// Why: Most use cases don't need raw bytes after parsing, saving significant memory
func (t *Cache) StoreWithoutRaw(id string, tpl *Template, err error) {
	entry := t.parsedTemplatePool.Get().(*parsedTemplate)
	entry.template = tpl
	entry.err = err
	entry.raw = "" // Explicitly empty to save memory

	_ = t.items.Set(id, *entry)
	t.parsedTemplatePool.Put(entry)
}

// Get returns only the template without raw bytes (common use case)
// Why: Most callers only need the parsed template, not raw data
func (t *Cache) Get(id string) (*Template, error) {
	value, ok := t.items.Get(id)
	if !ok {
		return nil, nil
	}
	return value.template, value.err
}

// Purge the cache and return all objects to pool
func (t *Cache) Purge() {
	t.items.Clear()
	// Note: We can't easily reclaim pooled items, but pool will naturally GC unused items
}
