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

// AuthProvider is an interface for authentication providers
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL
	LookupURLX(url string) authx.AuthStrategy
	// GetTemplatePaths returns all template paths for secret fetching
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches all secrets synchronously
	PreFetchSecrets() error
}
