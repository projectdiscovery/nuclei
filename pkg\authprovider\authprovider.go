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

var ErrNoAuthProvider = fmt.Errorf("no auth provider available")

// AuthProvider is the interface for auth providers  
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL and returns AuthStrategy
	LookupURLX(url string) authx.AuthStrategy
	// GetTemplatePaths returns all template paths for auth
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches all secrets synchronously
	// IMPORTANT: This MUST block until all secrets are fetched
	PreFetchSecrets() error
}
