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

// TestSetValueAndRebuildDropsStaleCookies pins that a cookie the live request no
// longer sends is not resurrected from the parse-time snapshot: probing "theme"
// must not carry the stale "session" value.
func TestSetValueAndRebuildDropsStaleCookies(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "theme=light; session=abc123")

	cloned := parsedCookieComponent(t, raw)

	// the live request dropped session after the component was parsed
	raw.Header.Set("Cookie", "theme=light")
	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "theme",
	}, "fr")
	require.NoError(t, err)
	require.Equal(t, "theme=fr", rebuilt.Header.Get("Cookie"))
}

// TestSetValueAndRebuildDropsStaleCookiesWithoutCookieHeader covers the extreme
// of the same case: the live request has no Cookie header left, so only the
// fuzzed cookie may survive.
func TestSetValueAndRebuildDropsStaleCookiesWithoutCookieHeader(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "theme=light; session=abc123")

	cloned := parsedCookieComponent(t, raw)

	raw.Header.Del("Cookie")
	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "theme",
	}, "fr")
	require.NoError(t, err)
	require.Equal(t, "theme=fr", rebuilt.Header.Get("Cookie"))
}

// TestSetValueAndRebuildPreservesDuplicateCookieNames pins that duplicate cookie
// names keep their own values and positions, instead of collapsing to whichever
// one a name-keyed map saw last.
func TestSetValueAndRebuildPreservesDuplicateCookieNames(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "sid=1; dup=x; dup=y")

	cloned := parsedCookieComponent(t, raw)

	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "sid",
	}, "probe")
	require.NoError(t, err)
	require.Equal(t, "sid=probe; dup=x; dup=y", rebuilt.Header.Get("Cookie"))
}

// TestSetValueAndRebuildFuzzesEveryDuplicateOfFuzzedCookie documents that when
// the fuzzed name itself is duplicated, every occurrence carries the payload:
// servers disagree on which duplicate wins, so the probe must not depend on it.
func TestSetValueAndRebuildFuzzesEveryDuplicateOfFuzzedCookie(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "dup=x; keep=1; dup=y")

	cloned := parsedCookieComponent(t, raw)

	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "dup",
	}, "probe")
	require.NoError(t, err)
	require.Equal(t, "dup=probe; keep=1; dup=probe", rebuilt.Header.Get("Cookie"))
}

// TestSetValueAndRebuildKeepsPayloadWhenFuzzedCookieRemoved makes sure dropping
// stale cookies never drops the payload itself, which would make the probe
// identical to the baseline request.
func TestSetValueAndRebuildKeepsPayloadWhenFuzzedCookieRemoved(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "theme=light; session=abc123")

	cloned := parsedCookieComponent(t, raw)

	// the live request dropped the very cookie being fuzzed
	raw.Header.Set("Cookie", "session=zzz999")
	rebuilt, err := SetValueAndRebuild(fuzz.GeneratedRequest{
		Request:   raw,
		Component: cloned,
		Key:       "theme",
	}, "fr")
	require.NoError(t, err)
	require.Equal(t, "session=zzz999; theme=fr", rebuilt.Header.Get("Cookie"))
}

func parsedCookieComponent(t *testing.T, req *retryablehttp.Request) component.Component {
	t.Helper()
	cookies := component.NewCookie()
	parsed, err := cookies.Parse(req)
	require.NoError(t, err)
	require.True(t, parsed)
	return cookies.Clone()
}

func cookieValue(t *testing.T, req *retryablehttp.Request, name string) string {
	t.Helper()
	cookie, err := req.Cookie(name)
	require.NoError(t, err)
	return cookie.Value
}
