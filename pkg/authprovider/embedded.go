package authprovider

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/stretchr/testify/require"
)

func TestNewEmbeddedAuthProvider(t *testing.T) {
	store := &authx.Authx{
		ID: "test-secrets",
		Info: authx.AuthFileInfo{
			Name:   "Test Secrets",
			Author: "test",
		},
		Secrets: []authx.Secret{
			{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []authx.KV{
					{Key: "X-API-Key", Value: "test-key"},
				},
			},
		},
	}

	provider, err := NewEmbeddedAuthProvider(store, nil)
	require.NoError(t, err)
	require.NotNil(t, provider)
}

func TestEmbeddedAuthProviderLookupAddr(t *testing.T) {
	store := &authx.Authx{
		ID: "test-secrets",
		Secrets: []authx.Secret{
			{
				Type:    "Header",
				Domains: []string{"example.com", "api.example.com"},
				Headers: []authx.KV{
					{Key: "X-API-Key", Value: "test-key"},
				},
			},
		},
	}

	provider, err := NewEmbeddedAuthProvider(store, nil)
	require.NoError(t, err)

	// Test exact domain match
	strategies := provider.LookupAddr("example.com")
	require.Len(t, strategies, 1)

	// Test domain with port normalization
	strategies = provider.LookupAddr("example.com:443")
	require.Len(t, strategies, 1)

	// Test non-matching domain
	strategies = provider.LookupAddr("other.com")
	require.Len(t, strategies, 0)
}

func TestEmbeddedAuthProviderWithRegex(t *testing.T) {
	store := &authx.Authx{
		ID: "test-secrets",
		Secrets: []authx.Secret{
			{
				Type:         "Header",
				DomainsRegex: []string{`.*\.example\.com`},
				Headers: []authx.KV{
					{Key: "X-API-Key", Value: "test-key"},
				},
			},
		},
	}

	provider, err := NewEmbeddedAuthProvider(store, nil)
	require.NoError(t, err)

	// Test regex match
	strategies := provider.LookupAddr("api.example.com")
	require.Len(t, strategies, 1)

	strategies = provider.LookupAddr("sub.example.com")
	require.Len(t, strategies, 1)

	// Test non-matching domain
	strategies = provider.LookupAddr("example.org")
	require.Len(t, strategies, 0)
}

func TestEmbeddedAuthProviderNoSecrets(t *testing.T) {
	store := &authx.Authx{
		ID: "test-secrets",
	}

	_, err := NewEmbeddedAuthProvider(store, nil)
	require.Error(t, err)
	require.Equal(t, ErrNoSecrets, err)
}

func TestEmbeddedAuthProviderNilStore(t *testing.T) {
	_, err := NewEmbeddedAuthProvider(nil, nil)
	require.Error(t, err)
}

func TestEmbeddedAuthProviderGetTemplatePaths(t *testing.T) {
	store := &authx.Authx{
		ID: "test-secrets",
		Secrets: []authx.Secret{
			{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []authx.KV{
					{Key: "X-API-Key", Value: "test-key"},
				},
			},
		},
	}

	provider, err := NewEmbeddedAuthProvider(store, nil)
	require.NoError(t, err)

	paths := provider.GetTemplatePaths()
	require.Empty(t, paths)
}