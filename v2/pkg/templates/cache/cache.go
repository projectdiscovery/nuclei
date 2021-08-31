package cache

import (
	"sync"
)

// Templates is a cache for caching and storing templates for reuse.
type Templates struct {
	items *sync.Map
}

// New returns a new templates cache
func New() *Templates {
	return &Templates{items: &sync.Map{}}
}

type parsedTemplateErrHolder struct {
	template interface{}
	err      error
}

// Has returns true if the cache has a template. The template
// is returned along with any errors if found.
func (t *Templates) Has(template string) (interface{}, error) {
	value, ok := t.items.Load(template)
	if !ok || value == nil {
		return nil, nil
	}
	templateError, ok := value.(parsedTemplateErrHolder)
	if !ok {
		return nil, nil
	}
	return templateError.template, templateError.err
}

// Store stores a template with data and error
func (t *Templates) Store(template string, data interface{}, err error) {
	t.items.Store(template, parsedTemplateErrHolder{template: data, err: err})
}
