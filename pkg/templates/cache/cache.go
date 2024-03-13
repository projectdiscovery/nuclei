package cache

import (
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Templates is a cache for caching and storing templates for reuse.
type Templates struct {
	items *mapsutil.SyncLockMap[string, parsedTemplateErrHolder]
}

// New returns a new templates cache
func New() *Templates {
	return &Templates{items: mapsutil.NewSyncLockMap[string, parsedTemplateErrHolder]()}
}

type parsedTemplateErrHolder struct {
	template interface{}
	err      error
}

// Has returns true if the cache has a template. The template
// is returned along with any errors if found.
func (t *Templates) Has(template string) (interface{}, error) {
	value, ok := t.items.Get(template)
	if !ok {
		return nil, nil
	}
	return value.template, value.err
}

// Store stores a template with data and error
func (t *Templates) Store(template string, data interface{}, err error) {
	_ = t.items.Set(template, parsedTemplateErrHolder{template: data, err: err})
}

// Purge the cache
func (t *Templates) Purge() {
	t.items.Clear()
}
