package normalize

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestURLCollapsesEquivalentForms(t *testing.T) {
	same := "http://acme.test/page"
	for _, raw := range []string{
		"http://acme.test/page",
		"http://ACME.test/page",
		"HTTP://acme.test/page",
		"http://acme.test:80/page",
		"http://acme.test/page/",
		"http://acme.test/page#section",
		"http://acme.test/page?utm_source=news&utm_campaign=q4",
	} {
		require.Equal(t, same, URL(raw), "%q addresses the same resource", raw)
	}
}

func TestURLKeepsDifferencesThatMatter(t *testing.T) {
	// path case is significant on most servers, so it is left alone
	require.NotEqual(t, URL("http://acme.test/page"), URL("http://acme.test/PAGE"))
	// a non-default port is part of the target
	require.NotEqual(t, URL("http://acme.test/page"), URL("http://acme.test:8080/page"))
	// so is the scheme
	require.NotEqual(t, URL("http://acme.test/page"), URL("https://acme.test/page"))
	// and a functional query parameter
	require.NotEqual(t, URL("http://acme.test/page"), URL("http://acme.test/page?id=1"))
}

func TestURLKeepsFunctionalParamsWhenStrippingTracking(t *testing.T) {
	got := URL("http://acme.test/search?q=admin&utm_source=news&page=2")
	require.Contains(t, got, "q=admin")
	require.Contains(t, got, "page=2")
	require.NotContains(t, got, "utm_source")
}

func TestURLKeepsDefaultPortForOtherSchemes(t *testing.T) {
	// 443 is only the default for https, so on http it is a real port
	require.Contains(t, URL("http://acme.test:443/page"), ":443")
	require.NotContains(t, URL("https://acme.test:443/page"), ":443")
}

func TestURLKeepsRootPath(t *testing.T) {
	// "/" is the path at the root, not a trailing slash to trim
	require.Equal(t, URL("http://acme.test/"), URL("http://acme.test/"))
	require.NotEmpty(t, URL("http://acme.test/"))
}

func TestURLHandlesIPv6(t *testing.T) {
	require.Equal(t, URL("http://[::1]:8080/page"), URL("http://[::1]:8080/page/"))
	require.Contains(t, URL("http://[::1]:8080/page"), "[::1]:8080")
	// the default port still goes
	require.NotContains(t, URL("http://[::1]:80/page"), ":80")
}

// The provider accepts bare hosts, ip:port and other non-URL values. Guessing
// at those would lose targets, so they come back untouched.
func TestURLLeavesUnparsableInputAlone(t *testing.T) {
	for _, raw := range []string{"", "   ", "not a url", "acme.test", "10.0.0.1:8080"} {
		require.Equal(t, raw, URL(raw))
	}
}

func TestOriginIgnoresPathQueryAndDefaultPort(t *testing.T) {
	same := "https://example.com"
	for _, raw := range []string{
		"https://example.com/a",
		"https://EXAMPLE.com/b?q=1#frag",
		"https://example.com:443/c",
	} {
		require.Equal(t, same, Origin(raw), "%q is the same origin", raw)
	}
	require.NotEqual(t, Origin("https://example.com/a"), Origin("http://example.com/a"))
	require.NotEqual(t, Origin("https://example.com/a"), Origin("https://other.test/a"))
	require.NotEqual(t, Origin("https://example.com/a"), Origin("https://example.com:8443/a"))
	require.Equal(t, "example.com", Origin("example.com"))
	require.Empty(t, Origin(""))
	require.Empty(t, Origin("not a url"))
}

func TestIsTrackingParam(t *testing.T) {
	require.True(t, IsTrackingParam("utm_source"))
	require.True(t, IsTrackingParam("UTM_SOURCE"))
	require.True(t, IsTrackingParam("fbclid"))
	require.False(t, IsTrackingParam("id"))
	require.False(t, IsTrackingParam("ref"), "a generic name can be functional")
}
