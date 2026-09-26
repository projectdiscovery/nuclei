package engine

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
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
func (m *mockAuthProvider) Close()                                       {}

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

		headers, cookies, _ := resolveAuthMaterial(provider, mustParseURL(t, "https://example.com/app"))

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
		headers, cookies, _ := resolveAuthMaterial(&mockAuthProvider{}, mustParseURL(t, "https://example.com/"))
		require.Empty(t, headers)
		require.Empty(t, cookies)
	})

	t.Run("nil provider is safe", func(t *testing.T) {
		headers, cookies, _ := resolveAuthMaterial(nil, mustParseURL(t, "https://example.com/"))
		require.Nil(t, headers)
		require.Nil(t, cookies)
	})

	t.Run("nil url is safe", func(t *testing.T) {
		headers, cookies, _ := resolveAuthMaterial(&mockAuthProvider{}, nil)
		require.Nil(t, headers)
		require.Nil(t, cookies)
	})

	t.Run("only cookies yields no extra headers", func(t *testing.T) {
		provider := &mockAuthProvider{strategies: []authx.AuthStrategy{
			authx.NewCookiesAuthStrategy(&authx.Secret{Cookies: []authx.Cookie{{Key: "sid", Value: "xyz"}}}),
		}}
		headers, cookies, _ := resolveAuthMaterial(provider, mustParseURL(t, "https://example.com/"))
		require.Empty(t, headers)
		require.Len(t, cookies, 1)
		require.Equal(t, "sid", cookies[0].Name)
	})
}

func TestApplyAuthHeaders_OriginScoped(t *testing.T) {
	provider := &mockAuthProvider{strategies: []authx.AuthStrategy{
		authx.NewHeadersAuthStrategy(&authx.Secret{Headers: []authx.KV{{Key: "Authorization", Value: "Bearer secret"}}}),
	}}
	p := &Page{
		options:   &Options{AuthProvider: provider},
		inputURL:  mustParseURL(t, "https://app.example.com:8443/start"),
		authMutex: &sync.RWMutex{},
	}

	t.Run("same origin receives auth", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://app.example.com:8443/api", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "browser-value")

		p.applyAuthHeaders(req)

		require.Equal(t, "Bearer secret", req.Header.Get("Authorization"))
	})

	t.Run("different host does not receive auth", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://cdn.example.com:8443/image.png", nil)
		require.NoError(t, err)

		p.applyAuthHeaders(req)

		require.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("different port does not receive auth", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://app.example.com:9443/image.png", nil)
		require.NoError(t, err)

		p.applyAuthHeaders(req)

		require.Empty(t, req.Header.Get("Authorization"))
	})
}

func TestSameOrigin_DefaultPorts(t *testing.T) {
	require.True(t, sameOrigin(
		mustParseURL(t, "https://example.com/path").URL,
		mustParseURL(t, "https://example.com:443/other").URL,
	))
	require.False(t, sameOrigin(
		mustParseURL(t, "http://example.com/path").URL,
		mustParseURL(t, "https://example.com/path").URL,
	))
}

func TestAuthRedirectClient_StripsHeadersCrossOrigin(t *testing.T) {
	received := make(chan string, 1)
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer crossOrigin.Close()

	sameOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossOrigin.URL, http.StatusFound)
	}))
	defer sameOrigin.Close()

	p := &Page{inputURL: mustParseURL(t, sameOrigin.URL)}
	client := p.authRedirectClient(&http.Client{}, []string{"Authorization", "Bearer secret"})
	req, err := http.NewRequest(http.MethodGet, sameOrigin.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret")

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Empty(t, <-received)
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
