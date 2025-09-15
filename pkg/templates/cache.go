package templates

import (
	"github.com/projectdiscovery/utils/conversion"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Templates is a cache for caching and storing templates for reuse.
type Cache struct {
	items *mapsutil.SyncLockMap[string, parsedTemplate]
}

// New returns a new templates cache
func NewCache() *Cache {
	return &Cache{
		items: mapsutil.NewSyncLockMap[string, parsedTemplate](),
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
	return value.template, conversion.Bytes(value.raw), value.err
}

// Store stores a template with data and error
func (t *Cache) Store(id string, tpl *Template, raw []byte, err error) {
	entry := parsedTemplate{
		template: tpl,
		err:      err,
		raw:      conversion.String(raw),
	}
	_ = t.items.Set(id, entry)
}

// StoreWithoutRaw stores a template without raw data for memory efficiency
func (t *Cache) StoreWithoutRaw(id string, tpl *Template, err error) {
	entry := parsedTemplate{
		template: tpl,
		err:      err,
		raw:      "",
	}
	_ = t.items.Set(id, entry)
}

// Get returns only the template without raw bytes
func (t *Cache) Get(id string) (*Template, error) {
	value, ok := t.items.Get(id)
	if !ok {
		return nil, nil
	}
	return value.template, value.err
}

// Purge the cache
func (t *Cache) Purge() {
	t.items.Clear()
}
