package authprovider

import (
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/stretchr/testify/require"
)

func TestNewAuthProviderFromData(t *testing.T) {
	t.Run("nil data returns error", func(t *testing.T) {
		provider, err := NewAuthProviderFromData(nil, nil)
		require.ErrorIs(t, err, ErrNoSecrets)
		require.Nil(t, provider)
	})

	t.Run("empty secrets returns error", func(t *testing.T) {
		data := &authx.Authx{}
		provider, err := NewAuthProviderFromData(data, nil)
		require.ErrorIs(t, err, ErrNoSecrets)
		require.Nil(t, provider)
	})

	t.Run("static secrets create provider", func(t *testing.T) {
		data := &authx.Authx{
			Secrets: []authx.Secret{
				{
					Type:    "BearerToken",
					Domains: []string{"example.com"},
					Token:   "test-token-123",
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.NoError(t, err)
		require.NotNil(t, provider)

		// Verify lookup by addr works
		strategies := provider.LookupAddr("example.com")
		require.NotEmpty(t, strategies, "should find strategy for example.com")

		// Verify lookup by URL works
		u, _ := url.Parse("https://example.com/api/v1")
		strategies = provider.LookupURL(u)
		require.NotEmpty(t, strategies, "should find strategy for URL")

		// Verify no match for unrelated domain
		strategies = provider.LookupAddr("other.com")
		require.Empty(t, strategies, "should not find strategy for other.com")
	})

	t.Run("multiple static secrets", func(t *testing.T) {
		data := &authx.Authx{
			Secrets: []authx.Secret{
				{
					Type:    "BearerToken",
					Domains: []string{"api.example.com"},
					Token:   "bearer-token",
				},
				{
					Type:     "BasicAuth",
					Domains:  []string{"admin.example.com"},
					Username: "admin",
					Password: "password",
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.NoError(t, err)
		require.NotNil(t, provider)

		// Both domains should resolve
		strategies := provider.LookupAddr("api.example.com")
		require.NotEmpty(t, strategies)

		strategies = provider.LookupAddr("admin.example.com")
		require.NotEmpty(t, strategies)
	})

	t.Run("invalid secret returns validation error", func(t *testing.T) {
		data := &authx.Authx{
			Secrets: []authx.Secret{
				{
					Type:    "InvalidType",
					Domains: []string{"example.com"},
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid inline secret")
		require.Nil(t, provider)
	})

	t.Run("dynamic secrets without callback returns error", func(t *testing.T) {
		data := &authx.Authx{
			Dynamic: []authx.Dynamic{
				{
					Secret: &authx.Secret{
						Type:    "Cookie",
						Domains: []string{"example.com"},
					},
					TemplatePath: "/path/to/template.yaml",
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "lazy fetch callback is required")
		require.Nil(t, provider)
	})

	t.Run("template paths empty for static-only provider", func(t *testing.T) {
		data := &authx.Authx{
			Secrets: []authx.Secret{
				{
					Type:    "BearerToken",
					Domains: []string{"example.com"},
					Token:   "token",
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.NoError(t, err)
		paths := provider.GetTemplatePaths()
		require.Empty(t, paths)
	})

	t.Run("provider path is inline marker", func(t *testing.T) {
		data := &authx.Authx{
			Secrets: []authx.Secret{
				{
					Type:    "BearerToken",
					Domains: []string{"example.com"},
					Token:   "token",
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.NoError(t, err)
		fp, ok := provider.(*FileAuthProvider)
		require.True(t, ok)
		require.Equal(t, "<inline>", fp.Path)
	})

	t.Run("regex domain matching", func(t *testing.T) {
		data := &authx.Authx{
			Secrets: []authx.Secret{
				{
					Type:         "BearerToken",
					DomainsRegex: []string{".*\\.example\\.com"},
					Token:        "regex-token",
				},
			},
		}
		provider, err := NewAuthProviderFromData(data, nil)
		require.NoError(t, err)
		require.NotNil(t, provider)

		strategies := provider.LookupAddr("api.example.com")
		require.NotEmpty(t, strategies, "regex should match api.example.com")

		strategies = provider.LookupAddr("other.com")
		require.Empty(t, strategies, "regex should not match other.com")
	})
}
