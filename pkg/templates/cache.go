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
	return &Cache{items: mapsutil.NewSyncLockMap[string, parsedTemplate]()}
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
	_ = t.items.Set(id, parsedTemplate{template: tpl, raw: conversion.String(raw), err: err})
}

// Purge the cache
func (t *Cache) Purge() {
	t.items.Clear()
}
