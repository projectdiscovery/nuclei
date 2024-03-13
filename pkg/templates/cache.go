package templates

import (
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Templates is a cache for caching and storing templates for reuse.
type Cache struct {
	items *mapsutil.SyncLockMap[string, parsedTemplateErrHolder]
}

// New returns a new templates cache
func NewCache() *Cache {
	return &Cache{items: mapsutil.NewSyncLockMap[string, parsedTemplateErrHolder]()}
}

type parsedTemplateErrHolder struct {
	template *Template
	err      error
}

// Has returns true if the cache has a template. The template
// is returned along with any errors if found.
func (t *Cache) Has(template string) (*Template, error) {
	value, ok := t.items.Get(template)
	if !ok {
		return nil, nil
	}
	return value.template, value.err
}

// Store stores a template with data and error
func (t *Cache) Store(template string, data *Template, err error) {
	_ = t.items.Set(template, parsedTemplateErrHolder{template: data, err: err})
}

// Purge the cache
func (t *Cache) Purge() {
	t.items.Clear()
}
