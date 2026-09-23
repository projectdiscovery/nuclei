package redirect

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
	require.NotNil(t, analyzers.GetAnalyzer("open_redirect"))
	require.Equal(t, "open_redirect", (&Analyzer{}).Name())
}

func TestGenerateProbes(t *testing.T) {
	const canary = "abc123.nucleicanary.invalid"
	probes := GenerateProbes(canary)
	require.NotEmpty(t, probes)
	for _, p := range probes {
		require.Contains(t, p, canary)
	}
}

func TestRedirectsToCanary(t *testing.T) {
	const canary = "abc123.nucleicanary.invalid"

	tests := []struct {
		name     string
		location string
		finalH   string
		want     bool
	}{
		{
			name:     "absolute Location to canary",
			location: "https://abc123.nucleicanary.invalid/",
			want:     true,
		},
		{
			name:     "scheme-relative Location to canary",
			location: "//abc123.nucleicanary.invalid/path",
			want:     true,
		},
		{
			name:     "backslash trick normalized to canary",
			location: "/\\abc123.nucleicanary.invalid/",
			want:     true,
		},
		{
			name:     "case-insensitive host match",
			location: "https://ABC123.NucleiCanary.Invalid/",
			want:     true,
		},
		{
			name:   "final URL host is canary (followed redirect)",
			finalH: "abc123.nucleicanary.invalid",
			want:   true,
		},
		{
			name:     "redirect to legitimate host is not a hit",
			location: "https://accounts.example.com/login",
			want:     false,
		},
		{
			name:     "relative path redirect is not a hit",
			location: "/dashboard",
			want:     false,
		},
		{
			name:     "canary only as path segment is not a hit",
			location: "https://example.com/abc123.nucleicanary.invalid",
			want:     false,
		},
		{
			name: "empty inputs",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, RedirectsToCanary(tc.location, tc.finalH, canary))
		})
	}
}

func TestRandomCanaryHost(t *testing.T) {
	h1 := randomCanaryHost()
	h2 := randomCanaryHost()
	require.True(t, strings.HasSuffix(h1, ".nucleicanary.invalid"))
	require.NotEqual(t, h1, h2)
}

func TestRedirectsToCanaryEmptyCanary(t *testing.T) {
	require.False(t, RedirectsToCanary("https://anything/", "anything", ""))
}

func TestAnalyzeUsesRedirectResponseReturnedWithError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("q"))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	raw, err := retryablehttp.NewRequest(http.MethodGet, srv.URL+"/?q=%2Fdashboard", nil)
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
			OriginalValue: "/dashboard",
		},
		HttpClient: client,
	})
	require.NoError(t, err)
	require.True(t, matched)
}
