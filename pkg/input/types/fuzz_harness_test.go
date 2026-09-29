package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawRequestFromFuzzDataSeedCorpus(t *testing.T) {
	entries, err := os.ReadDir("testdata/gofuzz-corpus")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join("testdata/gofuzz-corpus", entry.Name())
		data, err := os.ReadFile(path)
		require.NoError(t, err)

		require.Truef(t, fuzzRawRequestParsing(data), "seed %s should exercise the raw request parser fuzz path", entry.Name())

		raw, targetURL, ok := rawRequestFromFuzzData(data)
		require.Truef(t, ok, "seed %s should decode into a raw request", entry.Name())
		require.NotEmpty(t, raw)
		require.NotEmpty(t, targetURL)

		rr, err := ParseRawRequest(raw)
		require.NoErrorf(t, err, "seed %s generated raw request should parse", entry.Name())
		exerciseFuzzRequestResponse(rr)

		rr, err = ParseRawRequestWithURL(raw, targetURL)
		require.NoErrorf(t, err, "seed %s generated raw request should parse with URL", entry.Name())
		exerciseFuzzRequestResponse(rr)
	}
}

func TestRawRequestFromFuzzDataRejectsOversizeInput(t *testing.T) {
	data := make([]byte, fuzzMaxInputSize+1)
	raw, targetURL, ok := rawRequestFromFuzzData(data)
	require.False(t, ok)
	require.Empty(t, raw)
	require.Empty(t, targetURL)
}
