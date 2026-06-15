package crlf

import (
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("crlf"))
	require.Equal(t, "crlf", (&Analyzer{}).Name())
}

func TestGenerateProbes(t *testing.T) {
	probes := GenerateProbes("X-Crlf-abc", "deadbeef")
	require.NotEmpty(t, probes)
	for _, p := range probes {
		require.True(t, strings.ContainsAny(p, "\r\n"), "every probe must carry a CR or LF")
		require.Contains(t, p, "deadbeef")
	}
}

func TestDetectInjection(t *testing.T) {
	const (
		name  = "X-Crlf-abc"
		value = "deadbeef"
	)

	t.Run("injected header present", func(t *testing.T) {
		h := http.Header{}
		h.Set(name, value)
		require.True(t, DetectInjection(h, name, value))
	})

	t.Run("header name canonicalization still matches", func(t *testing.T) {
		h := http.Header{}
		// server emits lowercase, Go canonicalizes on read
		h["X-Crlf-Abc"] = []string{value}
		require.True(t, DetectInjection(h, name, value))
	})

	t.Run("injected Set-Cookie present", func(t *testing.T) {
		h := http.Header{}
		h.Add("Set-Cookie", "crlf="+value+"; Path=/")
		require.True(t, DetectInjection(h, name, value))
	})

	t.Run("different value is not a hit", func(t *testing.T) {
		h := http.Header{}
		h.Set(name, "somethingelse")
		require.False(t, DetectInjection(h, name, value))
	})

	t.Run("absent header is not a hit", func(t *testing.T) {
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		require.False(t, DetectInjection(h, name, value))
	})

	t.Run("nil and empty inputs are safe", func(t *testing.T) {
		require.False(t, DetectInjection(nil, name, value))
		require.False(t, DetectInjection(http.Header{}, "", value))
		require.False(t, DetectInjection(http.Header{}, name, ""))
	})
}

func TestRandomToken(t *testing.T) {
	require.NotEqual(t, randomToken(), randomToken())
	require.Len(t, randomToken(), 10)
}
