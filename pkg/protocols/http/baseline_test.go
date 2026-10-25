package http

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestBaselineContextKeyScopesAuthentication(t *testing.T) {
	const baseURL = "https://example.com"
	input := contextargs.NewWithInput(t.Context(), baseURL)

	req, err := retryablehttp.NewRequest(http.MethodGet, baseURL+"/control", nil)
	require.NoError(t, err)
	plainKey := baselineContextKey(baseURL, req, input)

	req.Header.Set("Authorization", "Bearer token")
	authKey := baselineContextKey(baseURL, req, input)
	require.NotEqual(t, plainKey, authKey)

	input.CookieJar.SetCookies(req.Request.URL, []*http.Cookie{{Name: "session", Value: "one"}})
	cookieKey := baselineContextKey(baseURL, req, input)
	require.NotEqual(t, authKey, cookieKey)

	req.RawQuery = "api_key=secret"
	queryKey := baselineContextKey(baseURL, req, input)
	require.NotEqual(t, cookieKey, queryKey)
}
