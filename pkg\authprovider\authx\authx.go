package authx

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// Globals contains the dynamic template based auth credentials fetched
// from executing a template
var Globals *SecretsCache

// SecretsCache is the cache for fetched secrets
type SecretsCache struct {
	mu   sync.RWMutex
	data map[string]interface{}
}

// NewSecretsCache creates a new SecretsCache
func NewSecretsCache() *SecretsCache {
	return &SecretsCache{
		data: make(map[string]interface{}),
	}
}

// Set sets a key value pair in the cache
func (s *SecretsCache) Set(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
}

// Get gets a value from the cache
func (s *SecretsCache) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return v, ok
}
