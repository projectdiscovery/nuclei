package httputil

import (
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestTrailingSlash(t *testing.T) {
	testcases := []struct {
		payload  string
		hasSlash bool
	}{
		{"{{BaseURL}}", false},
		{"{{BaseURL}}/", true},
		{"{{RootURL}}", false},
		{"{{RootURL}}/", true},
		{"{{randomvar}}", false},
		{"{{randomvar}}/", true},
		{"later/{{randomvar}}/", false},
	}

	for _, v := range testcases {
		if v.hasSlash != HasTrailingSlash(v.payload) {
			t.Errorf("expected %v but got %v for %v", v.hasSlash, HasTrailingSlash(v.payload), v.payload)
		}
	}
}

func TestPortUpdate(t *testing.T) {
	testcases := []struct {
		inputURL        string // input url
		CleanedInputURL string
		RequestPath     string // path which contains port
		CleanedPath     string // path after processing
	}{
		{"http://localhost:53/test", "http://localhost:8000/test", "{{BaseURL}}:8000/newpath", "{{BaseURL}}/newpath"},
		{"http://localhost:53/test", "http://localhost:8000/test", "{{RootURL}}:8000/newpath", "{{RootURL}}/newpath"},
		{"http://localhost:53/test", "http://localhost:53/test", "{{RootURL}}/newpath", "{{RootURL}}/newpath"},
		{"http://localhost/test", "http://localhost:8000/test", "{{RootURL}}:8000/newpath", "{{RootURL}}/newpath"},
		{"http://localhost/test", "http://localhost/test", "{{RootURL}}/newpath", "{{RootURL}}/newpath"},
	}
	for _, v := range testcases {
		parsed, _ := urlutil.Parse(v.inputURL)
		parsed, v.RequestPath = UpdateURLPortFromPayload(parsed, v.RequestPath)
		require.Equal(t, v.CleanedInputURL, parsed.String(), "could not get correct value")
		require.Equal(t, v.CleanedPath, v.RequestPath, "could not get correct data")
	}
}
