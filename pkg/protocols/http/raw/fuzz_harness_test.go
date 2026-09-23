package raw

import (
	"os"
	"path/filepath"
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestRawHTTPRequestFromFuzzDataSeedCorpus(t *testing.T) {
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

		require.Truef(t, fuzzRawHTTPParsing(data), "seed %s should exercise the raw HTTP parser fuzz path", entry.Name())

		rawRequest, inputURL, unsafe, disablePathAutomerge, ok := rawHTTPRequestFromFuzzData(data)
		require.Truef(t, ok, "seed %s should decode into a raw request", entry.Name())
		require.NotEmpty(t, rawRequest)
		require.NotEmpty(t, inputURL)

		parsedURL, err := urlutil.Parse(inputURL)
		require.NoErrorf(t, err, "seed %s should generate a valid input URL", entry.Name())

		request, err := Parse(rawRequest, parsedURL, unsafe, disablePathAutomerge)
		require.NoErrorf(t, err, "seed %s generated raw request should parse", entry.Name())
		exerciseFuzzRawRequest(request)

		request, err = ParseRawRequest(rawRequest, unsafe)
		if err == nil {
			exerciseFuzzRawRequest(request)
		}
	}
}

func TestRawHTTPRequestFromFuzzDataRejectsOversizeInput(t *testing.T) {
	data := make([]byte, fuzzMaxInputSize+1)
	rawRequest, inputURL, unsafe, disablePathAutomerge, ok := rawHTTPRequestFromFuzzData(data)
	require.False(t, ok)
	require.Empty(t, rawRequest)
	require.Empty(t, inputURL)
	require.False(t, unsafe)
	require.False(t, disablePathAutomerge)
}
