package memoize

import (
	"errors"

	"github.com/Mzack9999/gcache"
	"golang.org/x/sync/singleflight"
)

type Memoizer struct {
	cache gcache.Cache[string, interface{}]
	group singleflight.Group
}

type MemoizeOption func(m *Memoizer) error

func WithMaxSize(size int) MemoizeOption {
	return func(m *Memoizer) error {
		m.cache = gcache.New[string, interface{}](size).Build()
		return nil
	}
}

func New(options ...MemoizeOption) (*Memoizer, error) {
	m := &Memoizer{}
	for _, option := range options {
		if err := option(m); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *Memoizer) Do(funcHash string, fn func() (interface{}, error)) (interface{}, error, bool) {
	if value, err := m.cache.GetIFPresent(funcHash); !errors.Is(err, gcache.KeyNotFoundError) {
		return value, err, true
	}

	value, err, _ := m.group.Do(funcHash, func() (interface{}, error) {
		data, innerErr := fn()

		if innerErr == nil {
			m.cache.Set(funcHash, data)
		}

		return data, innerErr
	})

	return value, err, false
}
