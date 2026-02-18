package projectfile

import (
	"net/http"
	"os"
	"testing"
)

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
	if got.StatusCode != 200 {
		t.Errorf("HTTPS cache: expected status 200, got %d", got.StatusCode)
	}

	// Retrieve HTTP - should get 404
	got, err = pf.Get(reqData, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.StatusCode != 404 {
		t.Errorf("HTTP cache: expected status 404, got %d", got.StatusCode)
	}
}
