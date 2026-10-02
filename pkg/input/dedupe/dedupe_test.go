package dedupe

import (
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func mustURL(t *testing.T, raw string) urlutil.URL {
	t.Helper()
	parsed, err := urlutil.ParseAbsoluteURL(raw, false)
	require.NoError(t, err)
	return *parsed
}

func newReq(t *testing.T, method, rawURL, body string, headers map[string]string) *types.RequestResponse {
	t.Helper()
	om := mapsutil.NewOrderedMap[string, string]()
	for k, v := range headers {
		om.Set(k, v)
	}
	return &types.RequestResponse{
		URL: mustURL(t, rawURL),
		Request: &types.HttpRequest{
			Method:  method,
			Body:    body,
			Headers: om,
		},
	}
}

func TestRequestDeduplicatorDuplicates(t *testing.T) {
	t.Parallel()

	d := NewRequestDeduplicator()
	a := newReq(t, "GET", "https://example.com/a?b=2&a=1", "", nil)
	b := newReq(t, "GET", "https://example.com/a?a=1&b=2", "", nil) // query order differs
	c := newReq(t, "POST", "https://example.com/a?a=1&b=2", "", nil)

	require.False(t, d.IsDuplicate(a))
	require.True(t, d.IsDuplicate(b), "normalized query order should collide")
	require.False(t, d.IsDuplicate(c), "different method should not collide")
	require.Equal(t, 2, d.Len())
}

func TestRequestDeduplicatorIgnoresDynamicHeaders(t *testing.T) {
	t.Parallel()

	d := NewRequestDeduplicator()
	a := newReq(t, "GET", "https://example.com/x", "", map[string]string{
		"Cookie":     "a=1",
		"User-Agent": "ua-a",
		"X-Custom":   "keep",
	})
	b := newReq(t, "GET", "https://example.com/x", "", map[string]string{
		"Cookie":     "a=2",
		"User-Agent": "ua-b",
		"X-Custom":   "keep",
	})
	c := newReq(t, "GET", "https://example.com/x", "", map[string]string{
		"X-Custom": "other",
	})

	require.False(t, d.IsDuplicate(a))
	require.True(t, d.IsDuplicate(b), "dynamic headers should be ignored")
	require.False(t, d.IsDuplicate(c), "stable header change should not collide")
}

func TestRequestDeduplicatorBodyMatters(t *testing.T) {
	t.Parallel()

	d := NewRequestDeduplicator()
	a := newReq(t, "POST", "https://example.com/x", `{"a":1}`, nil)
	b := newReq(t, "POST", "https://example.com/x", `{"a":2}`, nil)

	require.False(t, d.IsDuplicate(a))
	require.False(t, d.IsDuplicate(b))
}

func TestNormalizeURLDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://example.com/path?b=2&a=1")
	require.NoError(t, err)
	original := u.RawQuery

	got, err := NormalizeURL(u)
	require.NoError(t, err)
	require.Equal(t, original, u.RawQuery)
	require.Contains(t, got, "a=1")
	require.Contains(t, got, "b=2")
}

func TestHashRequestEmptyPath(t *testing.T) {
	t.Parallel()

	a := newReq(t, "GET", "https://example.com", "", nil)
	b := newReq(t, "GET", "https://example.com/", "", nil)

	ha, err := HashRequest(a)
	require.NoError(t, err)
	hb, err := HashRequest(b)
	require.NoError(t, err)
	require.Equal(t, ha, hb)
}
