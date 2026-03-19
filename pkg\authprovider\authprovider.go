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

// AuthProvider is the interface for auth providers
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL and returns AuthStrategy
	LookupURLX(url string) authx.AuthStrategy
	// GetTemplatePaths returns template paths used by this auth provider
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches all secrets - must block until complete
	PreFetchSecrets() error
}

var ErrNoAuthProvider = fmt.Errorf("no auth provider available")
