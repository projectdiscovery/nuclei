package ai

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/utils/errkit"
)

// Resolver maps a prompt onto nuclei protocol primitives.
//
// Implementations must return a YAML fragment using the request blocks nuclei
// already understands, validated against nuclei-jsonschema.json before it is
// returned. Nuclei treats the result as untrusted input and parses it through
// the normal template path, so a resolver cannot introduce behaviour that a
// hand written template could not express.
type Resolver interface {
	Resolve(ctx context.Context, prompt string, model string) ([]byte, error)
}

var (
	resolverMutex sync.RWMutex
	resolver      Resolver
)

// RegisterResolver installs the process wide resolver. Provider selection and
// credentials live outside this package so every tool in the ecosystem can
// share one implementation rather than embedding its own client.
func RegisterResolver(value Resolver) {
	resolverMutex.Lock()
	defer resolverMutex.Unlock()

	resolver = value
}

// RegisteredResolver returns the installed resolver, if any.
func RegisteredResolver() Resolver {
	resolverMutex.RLock()
	defer resolverMutex.RUnlock()

	return resolver
}

// Store is the on disk cache of resolved fragments.
//
// Caching is what makes the protocol viable: expansion happens once per prompt
// for the lifetime of the cache, so a scan against ten thousand hosts costs the
// same as a scan against one, and repeat runs of a template behave identically.
type Store struct {
	dir string
}

// NewStore returns a cache rooted at dir. An empty dir uses the nuclei config
// directory.
func NewStore(dir string) *Store {
	if dir == "" {
		dir = filepath.Join(config.DefaultConfig.GetConfigDir(), "ai-cache")
	}

	return &Store{dir: dir}
}

// Get returns the cached fragment for a digest, or nil when absent.
func (store *Store) Get(digest string) ([]byte, error) {
	data, err := os.ReadFile(store.path(digest))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errkit.Wrap(err, "could not read cached expansion")
	}

	return data, nil
}

// Put stores the fragment for a digest.
func (store *Store) Put(digest string, fragment []byte) error {
	if err := os.MkdirAll(store.dir, 0750); err != nil {
		return errkit.Wrap(err, "could not create expansion cache directory")
	}

	if err := os.WriteFile(store.path(digest), fragment, 0600); err != nil {
		return errkit.Wrap(err, "could not write cached expansion")
	}

	return nil
}

func (store *Store) path(digest string) string {
	return filepath.Join(store.dir, digest+".yaml")
}
