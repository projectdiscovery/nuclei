package authx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestCookieAuthOwnershipIsRequestLocal(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	NewCookiesAuthStrategy(&Secret{Cookies: []Cookie{{Key: "session", Value: "configured"}}}).ApplyOnRR(req)
	cloned := req.Clone(req.Context())
	NewCookiesAuthStrategy(&Secret{Cookies: []Cookie{{Key: "other", Value: "configured"}}}).ApplyOnRR(cloned)
	require.True(t, IsAuthCookie(req.Context(), "session"))
	require.False(t, IsAuthCookie(req.Context(), "other"))
	require.True(t, IsAuthCookie(cloned.Context(), "session"))
	require.True(t, IsAuthCookie(cloned.Context(), "other"))
	require.False(t, IsAuthCookie(cloned.Context(), "Session"))

	NewHeadersAuthStrategy(&Secret{Headers: []KV{{Key: "Cookie", Value: "replacement=configured"}}}).ApplyOnRR(cloned)
	require.True(t, IsAuthCookie(cloned.Context(), "replacement"))
	require.False(t, IsAuthCookie(cloned.Context(), "session"))
	require.False(t, IsAuthCookie(cloned.Context(), "other"))
	require.True(t, IsAuthCookie(req.Context(), "session"))
}

func TestHeaderAuthCookieOwnershipIgnoresQuotedFragments(t *testing.T) {
	for _, header := range []string{`payload="a;session=probe"`, `payload="a\";session=probe"`, `payload="a;session=probe`} {
		t.Run(header, func(t *testing.T) {
			req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)
			NewCookiesAuthStrategy(&Secret{Cookies: []Cookie{{Key: "session", Value: "configured"}}}).ApplyOnRR(req)
			NewHeadersAuthStrategy(&Secret{Headers: []KV{{Key: "Cookie", Value: header}}}).ApplyOnRR(req)
			require.Equal(t, header, req.Header.Get("Cookie"))
			require.True(t, IsAuthCookie(req.Context(), "payload"))
			require.False(t, IsAuthCookie(req.Context(), "session"))
		})
	}
}
