package cors

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("cors"))
	require.Equal(t, "cors", (&Analyzer{}).Name())
}

func TestTestOrigins(t *testing.T) {
	const canary = "https://abc.corscanary.example"

	noHost := TestOrigins("", canary)
	require.Contains(t, noHost, canary)
	require.Contains(t, noHost, "null")

	withHost := TestOrigins("app.example.com", canary)
	require.Contains(t, withHost, "https://app.example.com.corscanary.example")
	require.Greater(t, len(withHost), len(noHost))
}

func TestAnalyzeCORS(t *testing.T) {
	const origin = "https://abc.corscanary.example"

	t.Run("reflected origin with credentials is critical", func(t *testing.T) {
		h := http.Header{}
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		reason, vuln := AnalyzeCORS(h, origin)
		require.True(t, vuln)
		require.Contains(t, reason, "Credentials")
	})

	t.Run("reflected origin without credentials still flagged", func(t *testing.T) {
		h := http.Header{}
		h.Set("Access-Control-Allow-Origin", origin)
		reason, vuln := AnalyzeCORS(h, origin)
		require.True(t, vuln)
		require.NotContains(t, reason, "Credentials")
	})

	t.Run("null origin reflected", func(t *testing.T) {
		h := http.Header{}
		h.Set("Access-Control-Allow-Origin", "null")
		_, vuln := AnalyzeCORS(h, "null")
		require.True(t, vuln)
	})

	t.Run("wildcard is not flagged as origin reflection", func(t *testing.T) {
		h := http.Header{}
		h.Set("Access-Control-Allow-Origin", "*")
		_, vuln := AnalyzeCORS(h, origin)
		require.False(t, vuln)
	})

	t.Run("legit origin echoing back our canary not present", func(t *testing.T) {
		h := http.Header{}
		h.Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		_, vuln := AnalyzeCORS(h, origin)
		require.False(t, vuln)
	})

	t.Run("no ACAO header", func(t *testing.T) {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		_, vuln := AnalyzeCORS(h, origin)
		require.False(t, vuln)
	})

	t.Run("nil and empty inputs are safe", func(t *testing.T) {
		_, vuln := AnalyzeCORS(nil, origin)
		require.False(t, vuln)
		_, vuln = AnalyzeCORS(http.Header{}, "")
		require.False(t, vuln)
	})
}
