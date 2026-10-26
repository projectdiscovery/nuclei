package runner

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
	"github.com/projectdiscovery/retryablehttp-go"
)

func mustReq(t *testing.T, raw string) *retryablehttp.Request {
	t.Helper()
	req, err := retryablehttp.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return req
}

func respFor(raw string, status int) *http.Response {
	u, _ := url.Parse(raw)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Server": []string{"probe"}},
		Request:    &http.Request{Method: http.MethodGet, URL: u},
	}
}

// The probe follows redirects. The body it comes back with belongs to the
// redirect target, so it must never be stored under the requested URL: a
// template asking for "/" must still see the redirect, not the target page.
func TestSeedFingerprintResponseAfterRedirect(t *testing.T) {
	const seedURL = "http://example.test/"
	const finalURL = "http://example.test/wp-admin/install.php"

	c := httprespcache.New()
	req := mustReq(t, seedURL)
	req.Header.Set("User-Agent", "probe-ua")
	seedFingerprintResponse(c, req, respFor(finalURL, 200), []byte("install page"), seedURL)

	lookup := req.Request.Clone(req.Context())
	if got := c.Get(httprespcache.KeyFromRequest(lookup), "template", lookup); got != nil {
		t.Fatal("the redirect target must not be cached under the requested URL")
	}

	finalLookup := req.Request.Clone(req.Context())
	finalLookup.URL, _ = url.Parse(finalURL)
	finalLookup.Host = ""
	if got := c.Get(httprespcache.KeyFromRequest(finalLookup), "template", finalLookup); got == nil {
		t.Fatal("the response must be cached under the URL it belongs to")
	}
}

// Without a redirect the response does describe the requested URL, so seeding
// it there is what saves the round trip.
func TestSeedFingerprintResponseWithoutRedirect(t *testing.T) {
	const seedURL = "http://example.test/"

	c := httprespcache.New()
	req := mustReq(t, seedURL)
	req.Header.Set("User-Agent", "probe-ua")
	seedFingerprintResponse(c, req, respFor(seedURL, 200), []byte("home"), seedURL)

	lookup := req.Request.Clone(req.Context())
	if got := c.Get(httprespcache.KeyFromRequest(lookup), "template", lookup); got == nil {
		t.Fatal("a non-redirected response must be cached under the requested URL")
	}
}
