package extractors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractorFromFuzzDataSeedCorpus(t *testing.T) {
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

		extractor, ok := extractorFromFuzzData(data)
		require.Truef(t, ok, "seed %s should decode into an extractor", entry.Name())
		require.NoErrorf(t, extractor.CompileExtractors(), "seed %s should compile", entry.Name())
		require.NotPanicsf(t, func() {
			exerciseFuzzExtractor(extractor)
		}, "seed %s should execute extraction paths", entry.Name())
	}
}

func TestExtractorFromFuzzDataRejectsOversizeInput(t *testing.T) {
	data := make([]byte, fuzzMaxInputSize+1)
	extractor, ok := extractorFromFuzzData(data)
	require.False(t, ok)
	require.Nil(t, extractor)
}

func TestExtractorFromFuzzDataFallbacksCompile(t *testing.T) {
	testcases := []string{
		"type=regex",
		"type=kval\ncase-insensitive=true",
		"type=json",
		"type=xpath",
		"type=dsl",
	}

	for _, testcase := range testcases {
		extractor, ok := extractorFromFuzzData([]byte(testcase))
		require.Truef(t, ok, "fallback input %q should decode", testcase)
		require.NoErrorf(t, extractor.CompileExtractors(), "fallback input %q should compile", testcase)
		require.NotPanicsf(t, func() {
			exerciseFuzzExtractor(extractor)
		}, "fallback input %q should execute extraction paths", testcase)
	}
}
