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

func TestParseRawRequestBodyTrailingNewlines(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		expectedBody string
	}{
		{
			name:         "single lf body",
			raw:          "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\n\n",
			expectedBody: "",
		},
		{
			name:         "crlf body",
			raw:          "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\n\r\n",
			expectedBody: "",
		},
		{
			name:         "empty body",
			raw:          "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
			expectedBody: "",
		},
		{
			name:         "body ending in lf",
			raw:          "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nA\n",
			expectedBody: "A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("ParseRawRequest", func(t *testing.T) {
				var rr *RequestResponse
				var err error
				require.NotPanics(t, func() {
					rr, err = ParseRawRequest(tt.raw)
				})
				require.NoError(t, err)
				require.NotNil(t, rr)
				require.Equal(t, tt.expectedBody, rr.Request.Body)
			})

			t.Run("ParseRawRequestWithURL", func(t *testing.T) {
				var rr *RequestResponse
				var err error
				require.NotPanics(t, func() {
					rr, err = ParseRawRequestWithURL(tt.raw, "http://example.com/")
				})
				require.NoError(t, err)
				require.NotNil(t, rr)
				require.Equal(t, tt.expectedBody, rr.Request.Body)
			})
		})
	}
}

func TestParseRawRequestHostHeaderIsCaseInsensitive(t *testing.T) {
	rr, err := ParseRawRequest("GET /path HTTP/1.1\r\nhost: example.com\r\nX-Test: value\r\n\r\n")
	require.NoError(t, err)
	require.Equal(t, "example.com", rr.URL.Host)
	host, ok := rr.Request.Headers.Get("host")
	require.True(t, ok)
	require.Equal(t, "example.com", host)
}

func TestParseRawRequestUppercaseAbsoluteTarget(t *testing.T) {
	rr, err := ParseRawRequest("GET HTTP://absolute.example/path?q=1 HTTP/1.1\r\nHost: ignored.example\r\n\r\n")
	require.NoError(t, err)
	require.Equal(t, "http", rr.URL.Scheme)
	require.Equal(t, "absolute.example", rr.URL.Host)
	require.Equal(t, "/path", rr.URL.Path)
	require.Equal(t, "q=1", rr.URL.RawQuery)
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

// BuildRequest used to dereference rr.Request unconditionally. Request is
// optional — UnmarshalJSON only sets it when a "request" key is present — so an
// entry carrying just a "url" (see TestUnmarshalJSON above, which relies on
// exactly that shape) panicked with a nil pointer dereference instead of
// returning an error, taking down the caller in pkg/protocols/http/request_fuzz.go.
func TestBuildRequestWithoutRequest(t *testing.T) {
	var rr RequestResponse
	err := rr.UnmarshalJSON([]byte(`{"url": "https://example.com/path"}`))
	require.NoError(t, err)
	require.Nil(t, rr.Request)

	require.NotPanics(t, func() {
		req, err := rr.BuildRequest()
		require.Error(t, err)
		require.Nil(t, req)
	})
}

// Guard rail: a request response that does carry a request must still build
// normally, so the nil check above can't be satisfied by refusing everything.
func TestBuildRequestWithRequestStillWorks(t *testing.T) {
	rr, err := ParseRawRequest("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	require.NotNil(t, rr.Request)

	req, err := rr.BuildRequest()
	require.NoError(t, err)
	require.NotNil(t, req)
	require.Equal(t, "GET", req.Method)
}
