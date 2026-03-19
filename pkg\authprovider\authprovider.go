package authprovider

import (
	"fmt"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// AuthProvider is a provider for authentication credentials
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL and returns AuthStrategy
	LookupURLX(url string) AuthStrategy
	// GetTemplatePaths returns all template paths for auth
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches all secrets from template-based auth providers
	PreFetchSecrets() error
}
