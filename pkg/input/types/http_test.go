package types

import (
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Possibly add more tests here.
func TestParseHttpRequest(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		url           string
		headerKey     string
		headerValue   string
		body          string
		contentLength string
	}{
		{"GET Request", "GET", "example.com/", "X-Test", "test", "", "0"},
		{"POST Request with body", "POST", "example.com/resource", "Content-Type", "application/json", `{"key":"value"}`, "15"},
		{"PUT Request with body", "PUT", "example.com/update", "Content-Type", "text/plain", "update data", "11"},
		{"DELETE Request", "DELETE", "example.com/delete", "X-User", "user1", "", "0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			}
			req, err := http.NewRequest(tc.method, "http://"+tc.url, bodyReader)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add(tc.headerKey, tc.headerValue)
			if tc.contentLength != "" {
				req.Header.Add("Content-Length", tc.contentLength)
			}
			binx, err := httputil.DumpRequestOut(req, true)
			if err != nil {
				t.Fatal(err)
			}
			rr, err := ParseRawRequest(string(binx))
			if err != nil {
				t.Fatal(err)
			}
			if rr.Request.Method != tc.method {
				t.Fatalf("invalid method: got %v want %v", rr.Request.Method, tc.method)
			}
			require.Equal(t, tc.url, rr.URL.String())
			val, _ := rr.Request.Headers.Get(tc.headerKey)
			require.Equal(t, tc.headerValue, val)
			if tc.body != "" {
				require.Equal(t, tc.body, rr.Request.Body)
				contentLengthVal, _ := rr.Request.Headers.Get("Content-Length")
				require.Equal(t, tc.contentLength, contentLengthVal)
			}

			t.Log(*rr.Request)
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name           string
		rawJSONStr     string
		expectedURLStr string
	}{
		{"basic url", `{"url": "example.com"}`, "example.com"},
		{"basic url with scheme", `{"url": "http://example.com"}`, "http://example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rr RequestResponse
			err := rr.UnmarshalJSON([]byte(tc.rawJSONStr))
			if err != nil {
				t.Fatal(err)
			}
			if tc.expectedURLStr != "" {
				require.Equal(t, rr.URL.String(), tc.expectedURLStr)
			}
		})
	}
}
