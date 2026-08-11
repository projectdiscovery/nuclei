package httprespcache

import (
	"io"
	"net/http"
	"net/http/httptest"
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
