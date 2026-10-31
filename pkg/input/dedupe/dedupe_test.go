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
		"Cookie":     "a=1; b=2",
		"User-Agent": "ua-a",
		"X-Custom":   "keep",
	})
	b := newReq(t, "GET", "https://example.com/x", "", map[string]string{
		"Cookie":     "b=2;a=1",
		"User-Agent": "ua-b",
		"X-Custom":   "keep",
	})
	c := newReq(t, "GET", "https://example.com/x", "", map[string]string{
		"X-Custom": "other",
	})

	require.False(t, d.IsDuplicate(a))
	require.True(t, d.IsDuplicate(b), "dynamic headers and cookie order should be ignored")
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

func TestHashRequestFieldBoundaries(t *testing.T) {
	t.Parallel()

	a := newReq(t, "GET", "https://example.com/x", "", map[string]string{"X-Ab": "c"})
	b := newReq(t, "GET", "https://example.com/x", "", map[string]string{"X-A": "bc"})

	ha, err := HashRequest(a)
	require.NoError(t, err)
	hb, err := HashRequest(b)
	require.NoError(t, err)
	require.NotEqual(t, ha, hb)
}

func TestHashRequestHostCaseAndFragment(t *testing.T) {
	t.Parallel()

	a := newReq(t, "GET", "https://Example.COM/x?a=1#top", "", nil)
	b := newReq(t, "GET", "https://example.com/x?a=1", "", nil)
	c := newReq(t, "GET", "https://example.com/X?a=1", "", nil)

	ha, err := HashRequest(a)
	require.NoError(t, err)
	hb, err := HashRequest(b)
	require.NoError(t, err)
	hc, err := HashRequest(c)
	require.NoError(t, err)
	require.Equal(t, ha, hb, "host case and fragment should not matter")
	require.NotEqual(t, hb, hc, "path case should matter")
}

func TestRequestDeduplicatorAuthHeadersMatter(t *testing.T) {
	t.Parallel()

	d := NewRequestDeduplicator()
	alice := newReq(t, "GET", "https://example.com/orders/1", "", map[string]string{"Authorization": "Bearer alice"})
	bob := newReq(t, "GET", "https://example.com/orders/1", "", map[string]string{"Authorization": "Bearer bob"})
	aliceAgain := newReq(t, "GET", "https://example.com/orders/1", "", map[string]string{"authorization": "bearer  alice "})
	anonymous := newReq(t, "GET", "https://example.com/orders/1", "", nil)

	require.False(t, d.IsDuplicate(alice))
	require.False(t, d.IsDuplicate(bob), "different authorization must not collide")
	require.True(t, d.IsDuplicate(aliceAgain), "scheme case and spacing should not matter")
	require.False(t, d.IsDuplicate(anonymous), "request without credentials must not collide")
	require.Equal(t, 3, d.Len())
}

func TestRequestDeduplicatorCookies(t *testing.T) {
	t.Parallel()

	d := NewRequestDeduplicator()
	a := newReq(t, "GET", "https://example.com/x", "", map[string]string{"Cookie": "session=alice; theme=dark"})
	b := newReq(t, "GET", "https://example.com/x", "", map[string]string{"Cookie": "theme=dark;session=alice;"})
	c := newReq(t, "GET", "https://example.com/x", "", map[string]string{"Cookie": "session=bob; theme=dark"})

	require.False(t, d.IsDuplicate(a))
	require.True(t, d.IsDuplicate(b), "cookie pair order should not matter")
	require.False(t, d.IsDuplicate(c), "different cookie value must not collide")
	require.Equal(t, 2, d.Len())
}

func TestRequestDeduplicatorWithoutAuthHeaders(t *testing.T) {
	t.Parallel()

	d := NewRequestDeduplicator()
	a := newReq(t, "GET", "https://example.com/x?b=2&a=1", "", map[string]string{"User-Agent": "a", "X-Request-Id": "1"})
	b := newReq(t, "GET", "https://example.com/x?a=1&b=2", "", map[string]string{"User-Agent": "b", "X-Request-Id": "2"})

	require.False(t, d.IsDuplicate(a))
	require.True(t, d.IsDuplicate(b))
	require.Equal(t, 1, d.Len())
}

func TestNormalizeCookie(t *testing.T) {
	t.Parallel()

	require.Equal(t, "a=1; b=2", normalizeCookie(" b=2 ;; a=1 ;"))
	require.Equal(t, "", normalizeCookie(""))
	require.Equal(t, "a=2; a=1", normalizeCookie("a=2; a=1"), "repeated names keep their order")
	require.Equal(t, "b=3; a=2; a=1", normalizeCookie("b=3; a=2; a=1"))
}

func TestHashRequestRepeatedCookieOrder(t *testing.T) {
	t.Parallel()

	a := newReq(t, "GET", "https://example.com/x", "", map[string]string{"Cookie": "session=alice; session=bob"})
	b := newReq(t, "GET", "https://example.com/x", "", map[string]string{"Cookie": "session=bob; session=alice"})

	ha, err := HashRequest(a)
	require.NoError(t, err)
	hb, err := HashRequest(b)
	require.NoError(t, err)
	require.NotEqual(t, ha, hb)
}

func TestNormalizeURLQuery(t *testing.T) {
	t.Parallel()

	normalize := func(raw string) string {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		got, err := NormalizeURL(u)
		require.NoError(t, err)
		return got
	}

	require.Equal(t, normalize("https://example.com/x?b=2&a=1"), normalize("https://example.com/x?a=1&b=2"), "key order should not matter")
	require.NotEqual(t, normalize("https://example.com/x?a=1&a=2"), normalize("https://example.com/x?a=2&a=1"), "order of repeated values should matter")
	require.NotEqual(t, normalize("https://example.com/x?a=1&probe=%ZZ"), normalize("https://example.com/x?a=1"), "malformed pairs should not be dropped")
	require.Equal(t, "https://example.com/x?a=1&probe=%ZZ", normalize("https://example.com/x?a=1&probe=%ZZ"))
}
