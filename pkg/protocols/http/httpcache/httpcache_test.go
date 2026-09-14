package httpcache

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync/atomic"
	"testing"
	"time"

	libcache "github.com/sandrolain/httpcache"
)

func dumpedResponse(t *testing.T, status int) []byte {
	t.Helper()
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	resp.Header.Set("Cache-Control", "max-age=60")
	data, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestStatusFilterCacheRejectsNon2xx(t *testing.T) {
	inner := libcache.NewMemoryCache()
	c := &statusFilterCache{inner: inner}

	okBody := dumpedResponse(t, http.StatusOK)
	c.Set("ok", okBody)
	got, ok := c.Get("ok")
	if !ok {
		t.Fatal("2xx response was not stored")
	}
	if string(got) != string(okBody) {
		t.Fatal("2xx cache payload changed")
	}

	c.Set("missing", dumpedResponse(t, http.StatusNotFound))
	if _, ok := c.Get("missing"); ok {
		t.Fatal("404 response was stored")
	}

	inner.Set("stale-404", dumpedResponse(t, http.StatusMovedPermanently))
	if _, ok := c.Get("stale-404"); ok {
		t.Fatal("existing 301 was served")
	}
}

func TestTransportDoesNotCache404(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "gone")
	}))
	t.Cleanup(ts.Close)

	rt := &libcache.Transport{
		Transport:                 ts.Client().Transport,
		Cache:                     &statusFilterCache{inner: libcache.NewMemoryCache()},
		SkipServerErrorsFromCache: true,
		AsyncRevalidateTimeout:    time.Second,
		ShouldCache:               shouldCache,
		DisableWarningHeader:      true,
	}

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("server hits = %d, want 2 (404 must not be reused from cache)", got)
	}
}

func TestTransportCaches200(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "%d", n)
	}))
	t.Cleanup(ts.Close)

	rt := &libcache.Transport{
		Transport:                 ts.Client().Transport,
		Cache:                     &statusFilterCache{inner: libcache.NewMemoryCache()},
		SkipServerErrorsFromCache: true,
		AsyncRevalidateTimeout:    time.Second,
		ShouldCache:               shouldCache,
		DisableWarningHeader:      true,
	}

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
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
		if string(body) != "1" {
			t.Fatalf("body = %q, want cached first response", body)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
}

func TestDiskCacheCloses(t *testing.T) {
	dir := t.TempDir()
	c, db, err := openDiskCache(dir, defaultMaxCacheBytes)
	if err != nil {
		t.Fatal(err)
	}
	body := dumpedResponse(t, http.StatusOK)
	c.Set("a", body)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("value missing before close")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	c2, db2, err := openDiskCache(dir, defaultMaxCacheBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	if _, ok := c2.Get("a"); !ok {
		t.Fatal("value missing after reopen")
	}
}

func TestDiskCacheRespectsSizeCap(t *testing.T) {
	dir := t.TempDir()
	c, db, err := openDiskCache(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	c.Set("a", dumpedResponse(t, http.StatusOK))
	if _, ok := c.Get("a"); ok {
		t.Fatal("stored a response over a 1-byte directory cap")
	}
}
