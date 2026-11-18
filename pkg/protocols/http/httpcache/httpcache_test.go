package httpcache

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	"go.dw1.io/x/net/http/cache"
)

// countingTransport counts the requests it sends to the server.
type countingTransport struct {
	next  http.RoundTripper
	count atomic.Int32
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.count.Add(1)
	return t.next.RoundTrip(req)
}

func get(t *testing.T, rt http.RoundTripper, url string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestClientsShareCache(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = fmt.Fprintf(w, "%d", n)
	}))
	t.Cleanup(ts.Close)

	c := openCache(filepath.Join(t.TempDir(), "snapshot"))
	a := &countingTransport{next: ts.Client().Transport}
	b := &countingTransport{next: ts.Client().Transport}
	clientA := newCachingTransport(c, a)
	clientB := newCachingTransport(c, b)

	if body := get(t, clientA, ts.URL+"/x"); body != "1" {
		t.Fatalf("first body = %q, want 1", body)
	}
	if body := get(t, clientB, ts.URL+"/x"); body != "1" {
		t.Fatalf("body for second client = %q, want the response cached for the first", body)
	}
	if body := get(t, clientB, ts.URL+"/y"); body != "2" {
		t.Fatalf("miss body = %q, want 2", body)
	}

	if got := a.count.Load(); got != 1 {
		t.Fatalf("first client sent %d requests, want 1", got)
	}
	if got := b.count.Load(); got != 1 {
		t.Fatalf("second client sent %d requests, want 1 (its miss only)", got)
	}
}

func TestEmptyRequestBodyUsesCache(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	rt := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	for range 2 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL, httpbody.New(nil))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
}

func TestEmptyPOSTBodySentUnchanged(t *testing.T) {
	type seen struct {
		contentLength    int64
		transferEncoding []string
	}
	var got []seen
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, seen{r.ContentLength, r.TransferEncoding})
	}))
	t.Cleanup(ts.Close)

	cached := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	for _, rt := range []http.RoundTripper{ts.Client().Transport, cached} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL, httpbody.New(nil))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	if len(got) != 2 || got[0].contentLength != got[1].contentLength ||
		fmt.Sprint(got[0].transferEncoding) != fmt.Sprint(got[1].transferEncoding) {
		t.Fatalf("server saw %+v, want the same request with and without the cache", got)
	}
}

func TestSnapshotSurvivesReopen(t *testing.T) {
	var full, revalidated atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			revalidated.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		_, _ = io.WriteString(w, "body")
	}))
	t.Cleanup(ts.Close)

	path := filepath.Join(t.TempDir(), "httpcache", "snapshot")
	first := openCache(path)
	firstClient := newCachingTransport(first, ts.Client().Transport)
	if body := get(t, firstClient, ts.URL); body != "body" {
		t.Fatalf("body = %q", body)
	}
	if err := saveSnapshot(first, path); err != nil {
		t.Fatal(err)
	}

	// The conditional request must go through the next RoundTripper given to
	// WithNext.
	client := &countingTransport{next: ts.Client().Transport}
	reopened := newCachingTransport(openCache(path), client)
	if body := get(t, reopened, ts.URL); body != "body" {
		t.Fatalf("body after reopen = %q, want the snapshot's", body)
	}
	if got := client.count.Load(); got != 1 {
		t.Fatalf("reopened client sent %d requests, want 1", got)
	}
	if got := full.Load(); got != 1 {
		t.Fatalf("server sent %d full responses, want 1", got)
	}
	if got := revalidated.Load(); got != 1 {
		t.Fatalf("server answered %d conditional requests, want 1", got)
	}
}

func TestCorruptSnapshotStartsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	path := filepath.Join(t.TempDir(), "snapshot")
	if err := os.WriteFile(path, []byte("not a snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := cache.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadSnapshot(c, path); !errors.Is(err, cache.ErrInvalidSnapshot) {
		t.Fatalf("loadSnapshot error = %v, want ErrInvalidSnapshot", err)
	}

	rt := newCachingTransport(openCache(path), ts.Client().Transport)
	if body := get(t, rt, ts.URL); body != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestCacheHitSkipsOriginAndBackoffSignal(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "busy")
	}))
	t.Cleanup(ts.Close)

	rt := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	first := roundTrip(t, rt, ts.URL, nil)
	if body := bodyOf(t, first); body != "busy" {
		t.Fatalf("body = %q", body)
	}
	if ServedFromCache(first) {
		t.Fatal("miss was reported as a cache hit")
	}
	if !ContactedOrigin(true, first) {
		t.Fatal("a live 503 must move host backoff")
	}
	second := roundTrip(t, rt, ts.URL, nil)
	if !ServedFromCache(second) {
		t.Fatal("second response was not served from the cache")
	}
	if ContactedOrigin(true, second) {
		t.Fatal("a pure cache hit must not move host backoff")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
}

func TestIdentityHeadersSkipCache(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = fmt.Fprintf(w, "%d %s", n, r.Header.Get("Authorization"))
	}))
	t.Cleanup(ts.Close)

	rt := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	if body := bodyOf(t, roundTrip(t, rt, ts.URL, nil)); body != "1 " {
		t.Fatalf("anonymous body = %q, want 1", body)
	}

	for _, header := range []string{"Authorization", "Cookie", "Origin"} {
		resp := roundTrip(t, rt, ts.URL, http.Header{header: {"secret"}})
		if ServedFromCache(resp) {
			t.Fatalf("%s request was served from the cache", header)
		}
		if body := bodyOf(t, resp); body == "1 " {
			t.Fatalf("%s request reused the anonymous response", header)
		}
	}

	if body := bodyOf(t, roundTrip(t, rt, ts.URL, nil)); body != "1 " {
		t.Fatalf("anonymous body after identity requests = %q, want the cached 1", body)
	}
}

func TestNonCanonicalIdentitySkipsCache(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = fmt.Fprintf(w, "%d", n)
	}))
	t.Cleanup(ts.Close)

	rt := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	if body := bodyOf(t, roundTrip(t, rt, ts.URL, nil)); body != "1" {
		t.Fatalf("anonymous body = %q", body)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["authorization"] = []string{"secret"}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if body := bodyOf(t, resp); body == "1" {
		t.Fatal("lowercase authorization reused the anonymous response")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hits = %d, want 2", got)
	}
}

func TestSetCookieIsNotReplayed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Add("Set-Cookie", "session=one")
		_, _ = io.WriteString(w, "page")
	}))
	t.Cleanup(ts.Close)

	rt := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	first := roundTrip(t, rt, ts.URL, nil)
	if body := bodyOf(t, first); body != "page" {
		t.Fatalf("body = %q", body)
	}
	if got := first.Header.Get("Set-Cookie"); got != "session=one" {
		t.Fatalf("caller Set-Cookie = %q", got)
	}

	second := roundTrip(t, rt, ts.URL, nil)
	if !ServedFromCache(second) {
		t.Fatal("response without relying on the cookie was not cached")
	}
	if got := second.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("cached response replayed Set-Cookie %q", got)
	}
}

func TestCredentialedPostInvalidatesCache(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "max-age=60")
		}
		_, _ = fmt.Fprintf(w, "%s %d", r.Method, n)
	}))
	t.Cleanup(ts.Close)

	rt := newCachingTransport(openCache(filepath.Join(t.TempDir(), "snapshot")), ts.Client().Transport)
	if body := bodyOf(t, roundTrip(t, rt, ts.URL, nil)); body != "GET 1" {
		t.Fatalf("first body = %q", body)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "secret")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	_ = bodyOf(t, resp)

	if body := bodyOf(t, roundTrip(t, rt, ts.URL, nil)); body != "GET 3" {
		t.Fatalf("body after credentialed POST = %q, want a fresh GET", body)
	}
}

func roundTrip(t *testing.T, rt http.RoundTripper, url string, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
