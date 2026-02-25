package analyzers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestXSSContextAnalyzer_Analyze(t *testing.T) {
	analyzer := &XSSContextAnalyzer{}

	t.Run("text-context-detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><body><div>pd_xss</div></body></html>")
		}))
		defer server.Close()

		opts := setupTestOptions(t, server.URL)
		found, context, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.True(t, found)
		require.Contains(t, context, "text:pd_xss")
	})

	t.Run("attribute-context-detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body><img src="pd_xss" /></body></html>`)
		}))
		defer server.Close()

		opts := setupTestOptions(t, server.URL)
		found, context, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, "attr:src:img", context)
	})

	t.Run("unknown-context-fallback", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "pd_xss")
		}))
		defer server.Close()

		opts := setupTestOptions(t, server.URL)
		found, context, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, "reflected:unknown", context)
	})

	t.Run("no-canary-detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><body>no reflection</body></html>")
		}))
		defer server.Close()

		opts := setupTestOptions(t, server.URL)
		found, _, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.False(t, found)
	})

	t.Run("nil-options-guard", func(t *testing.T) {
		found, _, err := analyzer.Analyze(nil)
		require.NoError(t, err)
		require.False(t, found)
	})
}

func setupTestOptions(t *testing.T, targetURL string) *Options {
	t.Helper()
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	req, err := retryablehttp.NewRequest("GET", targetURL, nil)
	require.NoError(t, err)

	return &Options{
		HttpClient: client,
		FuzzGenerated: fuzz.GeneratedRequest{
			Request: req,
			Value:   xssCanaryMarker,
		},
	}
}