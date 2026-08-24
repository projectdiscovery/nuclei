package hostheader

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
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
