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
	LookupURLX(url string) authx.AuthStrategy
	GetTemplatePaths() []string
	PreFetchSecrets() error
}

// FileAuthProvider is a file-based auth provider
type FileAuthProvider struct {
	Path           string
	store          *authx.AuthConfig
	mu             sync.RWMutex
	secretsFetched bool
	callback       func(authx.AuthStrategy)
}
