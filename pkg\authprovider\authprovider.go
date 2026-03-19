package authprovider

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v2"
)

// FileAuthProvider is a file-based auth provider implementing AuthProvider interface
type FileAuthProvider struct {
	Path      string
	store     *authx.AuthConfig
	fetched   bool
	fetchedMu sync.RWMutex
}

// PreFetchSecrets pre-fetches all secrets synchronously
// This MUST complete before scanning begins
func (f *FileAuthProvider) PreFetchSecrets() error {
	// implementation that blocks until complete
}
