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
func (t *Cache) Has(template string) (*Template, []byte, error) {
	value, ok := t.items.Get(template)
	if !ok {
		return nil, nil, nil
	}

	if value.raw != "" {
		return value.template, []byte(value.raw), value.err
	}
	return value.template, nil, value.err
}

// Store stores a template with data and error
func (t *Cache) Store(id string, tpl *Template, raw []byte, err error) {
	// Get parsedTemplate from pool instead of allocating new one
	entry := t.parsedTemplatePool.Get().(*parsedTemplate)

	entry.template = tpl
	entry.err = err

	if raw != nil {
		entry.raw = conversion.String(raw)
	} else {
		entry.raw = ""
	}

	_ = t.items.Set(id, *entry)

	t.parsedTemplatePool.Put(entry)
}

// StoreWithoutRaw stores a template without raw data for memory efficiency
func (t *Cache) StoreWithoutRaw(id string, tpl *Template, err error) {
	entry := t.parsedTemplatePool.Get().(*parsedTemplate)
	entry.template = tpl
	entry.err = err
	entry.raw = ""

	_ = t.items.Set(id, *entry)
	t.parsedTemplatePool.Put(entry)
}

// Get returns only the template without raw bytes (common use case)
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
