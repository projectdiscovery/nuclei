package hostheader

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("host_header_injection"))
	require.Equal(t, "host_header_injection", (&Analyzer{}).Name())
}

func TestReflectsCanary(t *testing.T) {
	const canary = "abc123.hostcanary.example"

	tests := []struct {
		name     string
		body     string
		location string
		want     bool
	}{
		{
			name:     "canary host in Location header",
			location: "https://abc123.hostcanary.example/reset?token=x",
			want:     true,
		},
		{
			name: "canary in absolute URL in body",
			body: `<a href="https://abc123.hostcanary.example/reset">reset</a>`,
			want: true,
		},
		{
			name: "canary in scheme-relative URL in body",
			body: `<script src="//abc123.hostcanary.example/app.js"></script>`,
			want: true,
		},
		{
			name: "canary after userinfo @ in body",
			body: `redirect to http://user@abc123.hostcanary.example/`,
			want: true,
		},
		{
			name:     "case-insensitive Location match",
			location: "https://ABC123.HostCanary.Example/",
			want:     true,
		},
		{
			name: "canary as bare substring is not a hit",
			body: `comment: abc123.hostcanary.example was mentioned in text`,
			want: false,
		},
		{
			name: "canary as hostname prefix is not a hit",
			body: `<a href="https://abc123.hostcanary.example.attacker.example/">reset</a>`,
			want: false,
		},
		{
			name: "canary as hostname suffix is not a hit",
			body: `<a href="https://prefix.abc123.hostcanary.example/">reset</a>`,
			want: false,
		},
		{
			name:     "unrelated location",
			location: "https://legit.example.com/home",
			body:     `<html>nothing</html>`,
			want:     false,
		},
		{
			name: "empty inputs",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ReflectsCanary(tc.body, tc.location, canary))
		})
	}
}

func TestReflectsCanaryEmptyCanary(t *testing.T) {
	require.False(t, ReflectsCanary("//anything/", "https://anything/", ""))
}

func TestRandomCanaryHost(t *testing.T) {
	h1 := randomCanaryHost()
	h2 := randomCanaryHost()
	require.True(t, strings.HasSuffix(h1, ".hostcanary.example"))
	require.NotEqual(t, h1, h2)
}

func TestOverrideHeadersNonEmpty(t *testing.T) {
	require.NotEmpty(t, overrideHeaders)
}

func TestForwardedOverrideUsesHostParameter(t *testing.T) {
	const canary = "abc123.hostcanary.example"
	require.Equal(t, "host="+canary, overrideHeaderValue("Forwarded", canary))
	require.Equal(t, canary, overrideHeaderValue("X-Forwarded-Host", canary))
}

func TestAnalyzeUsesRedirectResponseReturnedWithError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+r.Host+"/reset")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	raw, err := retryablehttp.NewRequest(http.MethodGet, srv.URL+"/?q=x", nil)
	require.NoError(t, err)
	query := component.NewQuery()
	parsed, err := query.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed)

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	client.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("stop redirect")
	}
	client.CheckRetry = func(context.Context, *http.Response, error) (bool, error) {
		return false, nil
	}

	matched, _, err := (&Analyzer{}).Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:       raw,
			Component:     query,
			Key:           "q",
			OriginalValue: "x",
		},
		HttpClient: client,
	})
	require.NoError(t, err)
	require.True(t, matched)
}
