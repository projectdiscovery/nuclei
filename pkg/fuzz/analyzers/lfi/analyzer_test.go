package lfi

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("lfi"))
	require.Equal(t, "lfi", (&Analyzer{}).Name())
}

func TestMatchFileSignature(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantFile string
		wantHit  bool
	}{
		{
			name: "etc passwd disclosed",
			body: "root:x:0:0:root:/root:/bin/bash\n" +
				"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
				"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
			wantFile: "/etc/passwd",
			wantHit:  true,
		},
		{
			name:     "etc passwd single nologin line",
			body:     `<pre>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</pre>`,
			wantFile: "/etc/passwd",
			wantHit:  true,
		},
		{
			name:     "windows win.ini fonts section",
			body:     "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n",
			wantFile: "win.ini",
			wantHit:  true,
		},
		{
			name:    "benign html no file",
			body:    `<html><body>Hello world, nothing to see here.</body></html>`,
			wantHit: false,
		},
		{
			name:    "colon separated text that is not passwd",
			body:    `time: 10:30:00 and ratio 4:3:2 here`,
			wantHit: false,
		},
		{
			name:    "empty body",
			body:    ``,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, hit := MatchFileSignature(tc.body)
			require.Equal(t, tc.wantHit, hit)
			if tc.wantHit {
				require.Equal(t, tc.wantFile, file)
			}
		})
	}
}

func TestTraversalPayloadsNonEmpty(t *testing.T) {
	require.NotEmpty(t, traversalPayloads)
	for _, p := range traversalPayloads {
		require.NotEmpty(t, p)
	}
}
