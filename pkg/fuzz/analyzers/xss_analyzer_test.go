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

	t.Run("no-canary-detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><body>no reflection here</body></html>")
		}))
		defer server.Close()

		opts := setupTestOptions(t, server.URL)
		found, _, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.False(t, found, "should not find canary")
	})

	t.Run("nil-options-guard", func(t *testing.T) {
		found, _, err := analyzer.Analyze(nil)
		require.NoError(t, err)
		require.False(t, found)
	})
}

// helper function to setup options with testing context
func setupTestOptions(t *testing.T, targetURL string) *Options {
	t.Helper()
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	req, err := retryablehttp.NewRequest("GET", targetURL, nil)
	require.NoError(t, err)

	return &Options{
		HttpClient: client,
		FuzzGenerated: fuzz.GeneratedRequest{
			Request: req,
			Value:   "pd_xss", // Setting the canary value explicitly
		},
	}
}