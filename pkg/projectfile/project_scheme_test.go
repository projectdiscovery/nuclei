package projectfile

import (
	"errors"
	"net/http"
	"os"
	"testing"
)

func TestSchemeNormalization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nuclei-project-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pf, err := New(&Options{Path: tmpDir, Cleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	reqData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}

	// Assert cache miss before any Set — confirms key doesn't pre-exist
	_, err = pf.Get(reqData, "https://example.com")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound before any Set, got: %v", err)
	}

	// Store with trailing slash
	if err := pf.Set(reqData, "https://example.com/", resp, []byte("body")); err != nil {
		t.Fatal(err)
	}

	// Retrieve without trailing slash - should hit same cache entry (normalization)
	got, err := pf.Get(reqData, "https://example.com")
	if err != nil {
		t.Fatalf("expected cache hit for normalized URL, got error: %v", err)
	}
	if got.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", got.StatusCode)
	}

	// Assert cache miss before next Set
	_, err = pf.Get(reqData, "https://other.com/path")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound before Set on other.com, got: %v", err)
	}

	// Store with explicit default port (443)
	if err := pf.Set(reqData, "https://other.com:443/path", resp, []byte("body2")); err != nil {
		t.Fatal(err)
	}

	// Retrieve without port - should hit same cache entry (default port stripped)
	got, err = pf.Get(reqData, "https://other.com/path")
	if err != nil {
		t.Fatalf("expected cache hit for URL without default port, got error: %v", err)
	}
	if got.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", got.StatusCode)
	}
}

func TestSchemeIsolation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nuclei-project-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pf, err := New(&Options{Path: tmpDir, Cleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	reqData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	httpsResp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Test": []string{"https"}},
	}
	httpResp := &http.Response{
		StatusCode: 404,
		Status:     "404 Not Found",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Test": []string{"http"}},
	}

	// Assert cache misses before any Set — confirms keys don't pre-exist
	_, err = pf.Get(reqData, "https://example.com")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("HTTPS: expected ErrNotFound before Set, got: %v", err)
	}
	_, err = pf.Get(reqData, "http://example.com")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("HTTP: expected ErrNotFound before Set, got: %v", err)
	}

	// Store HTTPS response
	if err := pf.Set(reqData, "https://example.com", httpsResp, []byte("https body")); err != nil {
		t.Fatal(err)
	}

	// Store HTTP response (different scheme, same host+path)
	if err := pf.Set(reqData, "http://example.com", httpResp, []byte("http body")); err != nil {
		t.Fatal(err)
	}

	// Retrieve HTTPS - should get 200
	got, err := pf.Get(reqData, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("HTTPS cache: expected non-nil response")
	}
	if got.StatusCode != 200 {
		t.Errorf("HTTPS cache: expected status 200, got %d", got.StatusCode)
	}

	// Retrieve HTTP - should get 404
	got, err = pf.Get(reqData, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("HTTP cache: expected non-nil response")
	}
	if got.StatusCode != 404 {
		t.Errorf("HTTP cache: expected status 404, got %d", got.StatusCode)
	}
}

func TestPortIsolation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nuclei-project-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pf, err := New(&Options{Path: tmpDir, Cleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	reqData := []byte("GET /api HTTP/1.1\r\nHost: target.internal\r\n\r\n")

	resp8080 := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Port": []string{"8080"}},
	}
	resp8443 := &http.Response{
		StatusCode: 403,
		Status:     "403 Forbidden",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Port": []string{"8443"}},
	}

	// Assert cache misses before any Set
	_, err = pf.Get(reqData, "http://target.internal:8080/api")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf(":8080: expected ErrNotFound before Set, got: %v", err)
	}
	_, err = pf.Get(reqData, "https://target.internal:8443/api")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf(":8443: expected ErrNotFound before Set, got: %v", err)
	}

	// Store responses for non-default ports
	if err := pf.Set(reqData, "http://target.internal:8080/api", resp8080, []byte("body8080")); err != nil {
		t.Fatal(err)
	}
	if err := pf.Set(reqData, "https://target.internal:8443/api", resp8443, []byte("body8443")); err != nil {
		t.Fatal(err)
	}

	// Port :8080 should return 200
	got, err := pf.Get(reqData, "http://target.internal:8080/api")
	if err != nil {
		t.Fatalf(":8080 lookup failed: %v", err)
	}
	if got.StatusCode != 200 {
		t.Errorf(":8080 expected 200, got %d", got.StatusCode)
	}

	// Port :8443 should return 403 (isolated from :8080)
	got, err = pf.Get(reqData, "https://target.internal:8443/api")
	if err != nil {
		t.Fatalf(":8443 lookup failed: %v", err)
	}
	if got.StatusCode != 403 {
		t.Errorf(":8443 expected 403, got %d", got.StatusCode)
	}

	// Cross-port lookup should miss — :8080 entry should NOT be retrievable via :8443 key
	_, err = pf.Get(reqData, "http://target.internal:8443/api")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-port lookup should miss, got: %v", err)
	}
}
