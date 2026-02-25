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

		opts := setupTestOptions(server.URL)
		found, context, err := analyzer.Analyze(opts)

		require.NoError(t, err)
		require.True(t, found)
		require.Contains(t, context, "text:pd_xss")
	})

	t.Run("attribute-context-detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><input value="pd_xss"></html>`)
		}))
		defer server.Close()

		opts := setupTestOptions(server.URL)
		found, context, err := analyzer.Analyze(opts)

		require.NoError(t, err)
		require.True(t, found)
		require.Contains(t, context, "attr:value:input")
	})

	t.Run("unknown-context-fallback", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Plain reflection without proper HTML tags context
			fmt.Fprint(w, "pd_xss reflection without tags")
		}))
		defer server.Close()

		opts := setupTestOptions(server.URL)
		found, context, err := analyzer.Analyze(opts)

		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, "reflected:unknown", context)
	})
}

func setupTestOptions(targetURL string) *Options {
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	req, _ := retryablehttp.NewRequest("GET", targetURL, nil)
	return &Options{
		HttpClient: client,
		FuzzGenerated: fuzz.GeneratedRequest{
			Request: req,
		},
	}
}