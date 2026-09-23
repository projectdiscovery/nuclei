package analyzers

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestSetValueAndRebuildRefreshesLiveCookies(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/?q=x", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "theme=light")

	query := component.NewQuery()
	parsed, err := query.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed)
	cloned := query.Clone()

	raw.Header.Set("Cookie", "theme=dark; session=abc123")
	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "q",
	}, "probe")
	require.NoError(t, err)
	require.Equal(t, "dark", cookieValue(t, rebuilt, "theme"))
	require.Equal(t, "abc123", cookieValue(t, rebuilt, "session"))
}

func TestSetValueAndRebuildMergesCookiesAroundFuzzedCookie(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "lang=en")

	cookies := component.NewCookie()
	parsed, err := cookies.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed)
	cloned := cookies.Clone()

	raw.Header.Set("Cookie", "lang=en; session=abc123")
	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "lang",
	}, "fr")
	require.NoError(t, err)
	require.Equal(t, "fr", cookieValue(t, rebuilt, "lang"))
	require.Equal(t, "abc123", cookieValue(t, rebuilt, "session"))
}

func cookieValue(t *testing.T, req *retryablehttp.Request, name string) string {
	t.Helper()
	cookie, err := req.Cookie(name)
	require.NoError(t, err)
	return cookie.Value
}
