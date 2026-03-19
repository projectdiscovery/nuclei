package authprovider

import (
	"fmt"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// AuthType is the type of auth provider
type AuthType string

const (
	BasicAuth  AuthType = "BasicAuth"
	BearerAuth AuthType = "BearerTokenAuth"
	CookieAuth AuthType = "CookiesAuth"
	HeaderAuth AuthType = "HeadersAuth"
	QueryAuth  AuthType = "QueryAuth"
	DynamicAuth AuthType = "DynamicAuth"
)

// AuthStrategy is the interface for auth strategies
type AuthStrategy interface {
	// Apply applies the auth strategy to the request
	Apply(args *AuthStrategyArgs) error
	// GetType returns the type of auth strategy
	GetType() AuthType
}

// AuthStrategyArgs contains the arguments for an auth strategy
type AuthStrategyArgs struct {
	// Request is the request to apply auth to
	Request interface{}
}

// AuthProvider is a provider for authentication credentials
type AuthProvider interface {
	// LookupURLX looks up credentials for a given URL
	LookupURLX(url string) AuthStrategy
	// GetTemplatePaths returns all template paths for auth
	GetTemplatePaths() []string
	// PreFetchSecrets pre-fetches all secrets
	PreFetchSecrets() error
}
