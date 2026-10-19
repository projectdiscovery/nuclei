package httprespcache

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCacheRoundTrip(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Server": []string{"nginx"}},
		Body:       io.NopCloser(http.NoBody),
	}
	c.Set(KeyFromRequest(req), resp, []byte("ok"))

	got := c.Get(KeyFromRequest(req), req)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "ok" {
		t.Fatalf("body=%q", body)
	}
	if got.Header.Get("Server") != "nginx" {
		t.Fatalf("header=%v", got.Header)
	}
	hits, misses, stores := c.Stats()
	if hits != 1 || misses != 0 || stores != 1 {
		t.Fatalf("stats hits=%d misses=%d stores=%d", hits, misses, stores)
	}
	if c.Get(Key(http.MethodGet, "http://example.com/other"), req) != nil {
		t.Fatal("expected miss")
	}
}

func TestCacheableRequest(t *testing.T) {
	get := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if !CacheableRequest(get) {
		t.Fatal("GET should be cacheable")
	}
	post := httptest.NewRequest(http.MethodPost, "http://x/", nil)
	if CacheableRequest(post) {
		t.Fatal("POST should not be cacheable")
	}
	auth := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	auth.Header.Set("Authorization", "Bearer t")
	if CacheableRequest(auth) {
		t.Fatal("Authorization must not be cacheable")
	}
	cookie := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	cookie.Header.Set("Cookie", "a=b")
	if CacheableRequest(cookie) {
		t.Fatal("Cookie must not be cacheable")
	}
	hostOverride := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	hostOverride.Host = "other.example"
	if CacheableRequest(hostOverride) {
		t.Fatal("Host override must not be cacheable")
	}
	cc := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	cc.Header.Set("Cache-Control", "no-cache")
	if CacheableRequest(cc) {
		t.Fatal("Cache-Control must not be cacheable")
	}
	pragma := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	pragma.Header.Set("Pragma", "no-cache")
	if CacheableRequest(pragma) {
		t.Fatal("Pragma must not be cacheable")
	}
}

func TestKeyFromRequestIncludesRepresentationHeaders(t *testing.T) {
	a := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	a.Header.Set("User-Agent", "ua-a")
	a.Header.Set("Accept-Language", "en")

	b := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	b.Header.Set("User-Agent", "ua-a")
	b.Header.Set("Accept-Language", "fr")

	if KeyFromRequest(a) == KeyFromRequest(b) {
		t.Fatal("distinct Accept-Language must produce distinct keys")
	}

	c := New()
	c.Set(KeyFromRequest(a), &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("en-body"))
	if c.Get(KeyFromRequest(b), b) != nil {
		t.Fatal("must not reuse response across Accept-Language")
	}
	if got := c.Get(KeyFromRequest(a), a); got == nil {
		t.Fatal("expected hit for matching headers")
	}
}

func TestCacheDisabled(t *testing.T) {
	c := New()
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Set(KeyFromRequest(req), &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("x"))
	c.Disable()
	if c.Get(KeyFromRequest(req), req) != nil {
		t.Fatal("disabled cache must miss")
	}
	c.Set(KeyFromRequest(req), &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("y"))
	if c.Enabled() {
		t.Fatal("expected disabled")
	}
}

func TestCacheEntryBudget(t *testing.T) {
	c := New()
	c.maxEntries = 2
	c.maxBytes = 100
	mk := func(path, body string) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		c.Set(KeyFromRequest(req), &http.Response{StatusCode: 200, Header: http.Header{}}, []byte(body))
	}
	mk("/a", "aa")
	mk("/b", "bb")
	mk("/c", "cc") // over entry budget
	if c.Len() != 2 {
		t.Fatalf("len=%d want 2", c.Len())
	}
	if c.skipped.Load() == 0 {
		t.Fatal("expected skipped store")
	}

	c2 := New()
	c2.maxEntries = 10
	c2.maxBytes = 5
	mk2 := func(path, body string) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		c2.Set(KeyFromRequest(req), &http.Response{StatusCode: 200, Header: http.Header{}}, []byte(body))
	}
	mk2("/a", "12345")
	mk2("/b", "x") // over byte budget
	if c2.Len() != 1 {
		t.Fatalf("byte budget len=%d want 1", c2.Len())
	}
}

func TestCacheableRequestEmptyBody(t *testing.T) {
	// Raw templates hand over a non-nil but empty reader with ContentLength 0.
	// That request is bodyless on the wire, so it stays cacheable.
	empty := httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader(""))
	empty.ContentLength = 0
	if empty.Body == nil {
		t.Fatal("test needs a non-nil body")
	}
	if !CacheableRequest(empty) {
		t.Fatal("GET with an empty body should be cacheable")
	}

	// A GET that really carries bytes is excluded: the body is part of the
	// request identity but is not part of the cache key.
	withBody := httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader("payload"))
	withBody.ContentLength = int64(len("payload"))
	if CacheableRequest(withBody) {
		t.Fatal("GET with a payload must not be cacheable")
	}

	// Unknown length is treated as a payload.
	unknown := httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader("payload"))
	unknown.ContentLength = -1
	if CacheableRequest(unknown) {
		t.Fatal("GET with an unknown body length must not be cacheable")
	}
}

func TestCacheableRequestHostHeader(t *testing.T) {
	// Raw templates repeat the target host in a Host header. net/http drops it
	// and sends the URL host, so the request is unchanged and stays cacheable.
	same := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	same.Header.Set("Host", "x.example")
	if !CacheableRequest(same) {
		t.Fatal("redundant Host header should stay cacheable")
	}

	withDefaultPort := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	withDefaultPort.Header.Set("Host", "x.example:80")
	if !CacheableRequest(withDefaultPort) {
		t.Fatal("Host header with the default port should stay cacheable")
	}

	// A different Host is a deliberate override and must not share a response.
	other := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	other.Header.Set("Host", "evil.example")
	if CacheableRequest(other) {
		t.Fatal("Host override must not be cacheable")
	}

	otherPort := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	otherPort.Header.Set("Host", "x.example:8080")
	if CacheableRequest(otherPort) {
		t.Fatal("Host header with a different port must not be cacheable")
	}
}
