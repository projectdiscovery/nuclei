package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestBuiltInAnalyzersRegistered(t *testing.T) {
	names := []string{
		"cmdi",
		"cors",
		"crlf",
		"host_header_injection",
		"lfi",
		"open_redirect",
		"sqli_error",
		"ssrf",
		"ssti",
		"time_delay",
		"xss_context",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			require.NotNil(t, analyzers.GetAnalyzer(name))
		})
	}
}
