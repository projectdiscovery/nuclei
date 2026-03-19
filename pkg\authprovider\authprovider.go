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

// AuthProvider is the interface for providing authentication
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL
	LookupURLX(url string) authx.AuthStrategy
	// GetTemplatePaths returns all template paths for auth
	GetTemplatePaths() []string
	// PreFetchSecrets synchronously pre-fetches all secrets
	PreFetchSecrets() error
}

var ErrNoAuthProvider = fmt.Errorf("no auth provider found")
