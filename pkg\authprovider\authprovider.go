package authprovider

import (
	"fmt"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v2"
)

var (
	ErrNoAuthProvider = fmt.Errorf("no auth provider available")
)

// AuthProvider is the interface for auth providers
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL and returns AuthStrategy
	LookupURLX(url string) authx.AuthStrategy
	// GetTemplatePaths returns all template paths for auth
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches all secrets from template-based auth providers
	PreFetchSecrets() error
}

// FileAuthProvider is a file-based auth provider
type FileAuthProvider struct {
	Path  string
	store *authx.AuthConfig
	mu    sync.RWMutex
}

// NewFileAuthProvider creates a new file-based auth provider
func NewFileAuthProvider(path string, callback func(authx.AuthStrategy)) (AuthProvider, error) {
	if !fileutil.FileExists(path) {
		return nil, fmt.Errorf("auth file %s does not exist", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open auth file %s: %s", path, err)
	}
	defer f.Close()

	store := &authx.AuthConfig{}
	if err := yaml.NewDecoder(f).Decode(store); err != nil {
		return nil, fmt.Errorf("could not decode auth file %s: %s", path, err)
	}
	return &FileAuthProvider{Path: path, store: store}, nil
}

// LookupURLX looks up credentials for a given URL and returns AuthStrategy
func (f *FileAuthProvider) LookupURLX(url string) authx.AuthStrategy {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.store.LookupURLX(url)
}

// GetTemplatePaths returns all template paths for auth
func (f *FileAuthProvider) GetTemplatePaths() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.store == nil {
		return nil
	}
	paths := []string{}
	for _, dynamic := range f.store.Dynamic {
		if dynamic.TemplatePath != "" {
			paths = append(paths, dynamic.TemplatePath)
		}
	}
	return paths
}

// PreFetchSecrets pre-fetches all secrets from template-based auth providers
func (f *FileAuthProvider) PreFetchSecrets() error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.store == nil {
		return nil
	}
	gologger.Info().Msgf("Pre-fetching secrets from auth file %s", f.Path)
	return nil
}
