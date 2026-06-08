package cmdi

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("cmdi"))
	require.Equal(t, "cmdi", (&Analyzer{}).Name())
}

func TestMatchCommandOutput(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "classic root id output",
			body: `uid=0(root) gid=0(root) groups=0(root)`,
			want: true,
		},
		{
			name: "non-root id output embedded in html",
			body: `<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>`,
			want: true,
		},
		{
			name: "id output with extra spacing",
			body: "uid=1000(deploy)   gid=1000(deploy) groups=1000(deploy),27(sudo)",
			want: true,
		},
		{
			name: "reflected payload but no execution",
			body: `You searched for: ;id - no results found`,
			want: false,
		},
		{
			name: "benign body",
			body: `<html><body>welcome</body></html>`,
			want: false,
		},
		{
			name: "uid mentioned without gid structure",
			body: `the uid=5 field is set`,
			want: false,
		},
		{
			name: "empty body",
			body: ``,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, MatchCommandOutput(tc.body))
		})
	}
}

func TestCommandSeparatorsNonEmpty(t *testing.T) {
	require.NotEmpty(t, commandSeparators)
	for _, s := range commandSeparators {
		require.NotEmpty(t, s)
	}
}
