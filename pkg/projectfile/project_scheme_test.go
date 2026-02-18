package projectfile

import (
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

	// Store with trailing slash
	if err := pf.Set(reqData, "https://example.com/", resp, []byte("body")); err != nil {
		t.Fatal(err)
	}

	// Retrieve without trailing slash - should hit same cache entry
	got, err := pf.Get(reqData, "https://example.com")
	if err != nil {
		t.Fatalf("expected cache hit for normalized URL, got error: %v", err)
	}
	if got.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", got.StatusCode)
	}

	// Store with default port
	if err := pf.Set(reqData, "https://other.com:443/path", resp, []byte("body2")); err != nil {
		t.Fatal(err)
	}

	// Retrieve without port - should hit same cache entry
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
