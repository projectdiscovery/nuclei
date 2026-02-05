package authprovider

import (
	"fmt"
	"net/url"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/utils/errkit"
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

// NewAuthProviderFromData creates a new auth provider from already-parsed secrets
func NewAuthProviderFromData(data *authx.Authx, callback authx.LazyFetchSecret) (AuthProvider, error) {
	if data == nil {
		return nil, ErrNoSecrets
	}
	if len(data.Secrets) == 0 && len(data.Dynamic) == 0 {
		return nil, ErrNoSecrets
	}
	if len(data.Dynamic) > 0 && callback == nil {
		return nil, errkit.New("lazy fetch callback is required for dynamic secrets")
	}
	
	// Validate static secrets
	for _, _secret := range data.Secrets {
		secret := _secret // Create copy to avoid issues
		if err := secret.Validate(); err != nil {
			errorErr := errkit.FromError(err)
			errorErr.Msgf("invalid secret in inline config")
			return nil, errorErr
		}
	}
	
	// Validate and setup dynamic secrets
	for i, _dynamic := range data.Dynamic {
		dynamic := _dynamic // Create copy
		if err := dynamic.Validate(); err != nil {
			errorErr := errkit.FromError(err)
			errorErr.Msgf("invalid dynamic secret in inline config")
			return nil, errorErr
		}
		dynamic.SetLazyFetchCallback(callback)
		data.Dynamic[i] = dynamic
	}
	
	// Create provider using same logic as FileAuthProvider
	provider := &FileAuthProvider{
		Path:  "inline-secrets",
		store: data,
	}
	provider.init()
	return provider, nil
}