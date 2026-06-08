package engine

import (
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

// mockAuthProvider is a minimal AuthProvider that returns a fixed set of
// strategies for any URL, used to exercise resolveAuthMaterial without a file.
type mockAuthProvider struct {
	strategies []authx.AuthStrategy
}

func (m *mockAuthProvider) LookupAddr(string) []authx.AuthStrategy       { return m.strategies }
func (m *mockAuthProvider) LookupURL(*url.URL) []authx.AuthStrategy      { return m.strategies }
func (m *mockAuthProvider) LookupURLX(*urlutil.URL) []authx.AuthStrategy { return m.strategies }
func (m *mockAuthProvider) GetTemplatePaths() []string                   { return nil }
func (m *mockAuthProvider) PreFetchSecrets() error                       { return nil }

func mustParseURL(t *testing.T, raw string) *urlutil.URL {
	t.Helper()
	u, err := urlutil.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestResolveAuthMaterial(t *testing.T) {
	t.Run("headers, bearer and cookies", func(t *testing.T) {
		provider := &mockAuthProvider{strategies: []authx.AuthStrategy{
			authx.NewHeadersAuthStrategy(&authx.Secret{Headers: []authx.KV{{Key: "X-Api-Key", Value: "secret"}}}),
			authx.NewBearerTokenAuthStrategy(&authx.Secret{Token: "tok123"}),
			authx.NewCookiesAuthStrategy(&authx.Secret{Cookies: []authx.Cookie{{Key: "session", Value: "abc"}}}),
		}}

		headers, cookies := resolveAuthMaterial(provider, mustParseURL(t, "https://example.com/app"))

		headerMap := pairsToMap(t, headers)
		require.Equal(t, "secret", headerMap["X-Api-Key"])
		require.Equal(t, "Bearer tok123", headerMap["Authorization"])
		// the Cookie header must not leak into extra headers
		_, hasCookieHeader := headerMap["Cookie"]
		require.False(t, hasCookieHeader, "Cookie header must be handled as a cookie, not an extra header")

		require.Len(t, cookies, 1)
		require.Equal(t, "session", cookies[0].Name)
		require.Equal(t, "abc", cookies[0].Value)
	})

	t.Run("no strategies returns nothing", func(t *testing.T) {
		headers, cookies := resolveAuthMaterial(&mockAuthProvider{}, mustParseURL(t, "https://example.com/"))
		require.Empty(t, headers)
		require.Empty(t, cookies)
	})

	t.Run("nil provider is safe", func(t *testing.T) {
		headers, cookies := resolveAuthMaterial(nil, mustParseURL(t, "https://example.com/"))
		require.Nil(t, headers)
		require.Nil(t, cookies)
	})

	t.Run("nil url is safe", func(t *testing.T) {
		headers, cookies := resolveAuthMaterial(&mockAuthProvider{}, nil)
		require.Nil(t, headers)
		require.Nil(t, cookies)
	})

	t.Run("only cookies yields no extra headers", func(t *testing.T) {
		provider := &mockAuthProvider{strategies: []authx.AuthStrategy{
			authx.NewCookiesAuthStrategy(&authx.Secret{Cookies: []authx.Cookie{{Key: "sid", Value: "xyz"}}}),
		}}
		headers, cookies := resolveAuthMaterial(provider, mustParseURL(t, "https://example.com/"))
		require.Empty(t, headers)
		require.Len(t, cookies, 1)
		require.Equal(t, "sid", cookies[0].Name)
	})
}

// pairsToMap converts the flat [k1,v1,k2,v2,...] header slice into a map.
func pairsToMap(t *testing.T, pairs []string) map[string]string {
	t.Helper()
	require.Zero(t, len(pairs)%2, "header pairs must be even length")
	m := make(map[string]string, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m
}
