package matchers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatcherFromFuzzDataSeedCorpus(t *testing.T) {
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

		matcher, ok := matcherFromFuzzData(data)
		require.Truef(t, ok, "seed %s should decode into a matcher", entry.Name())
		require.NoErrorf(t, matcher.CompileMatchers(), "seed %s should compile", entry.Name())
	}
}

func TestMatcherFromFuzzDataRejectsOversizeInput(t *testing.T) {
	data := make([]byte, fuzzMaxInputSize+1)
	matcher, ok := matcherFromFuzzData(data)
	require.False(t, ok)
	require.Nil(t, matcher)
}
