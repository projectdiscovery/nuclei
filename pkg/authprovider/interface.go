package authprovider

import (
	"fmt"
	"net/url"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	ErrNoSecrets = fmt.Errorf("no secrets in given provider")
)

var (
	_ AuthProvider = &FileAuthProvider{}
)

// AuthProvider is an interface for auth providers
// It implements a data structure suitable for quick lookup and retrieval
// of auth strategies
type AuthProvider interface {
	// LookupAddr looks up a given domain/address and returns appropriate auth strategy
	// for it (accepted inputs are scanme.sh or scanme.sh:443)
	LookupAddr(string) []authx.AuthStrategy
	// LookupURL looks up a given URL and returns appropriate auth strategy
	// it accepts a valid url struct and returns the auth strategy
	LookupURL(*url.URL) []authx.AuthStrategy
	// LookupURLX looks up a given URL and returns appropriate auth strategy
	// it accepts pd url struct (i.e urlutil.URL) and returns the auth strategy
	LookupURLX(*urlutil.URL) []authx.AuthStrategy
	// GetTemplatePaths returns the template path for the auth provider
	// that will be used for dynamic secret fetching
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches the secrets from the auth provider
	// instead of lazy fetching
	PreFetchSecrets() error
}

// AuthProviderOptions contains options for the auth provider
type AuthProviderOptions struct {
	// File based auth provider options
	SecretsFiles []string
	// LazyFetchSecret is a callback for lazy fetching of dynamic secrets
	LazyFetchSecret authx.LazyFetchSecret
}

// NewAuthProvider creates a new auth provider from the given options
func NewAuthProvider(options *AuthProviderOptions) (AuthProvider, error) {
	var providers []AuthProvider
	for _, file := range options.SecretsFiles {
		provider, err := NewFileAuthProvider(file, options.LazyFetchSecret)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	return NewMultiAuthProvider(providers...), nil
}
