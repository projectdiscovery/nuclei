package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateFromFuzzDataSeedCorpus(t *testing.T) {
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

		candidate := newFuzzTemplateCandidate(data)
		candidate.applyLines(splitFuzzLines(data))

		require.NoErrorf(t, exerciseFuzzYAMLTemplateErr(candidate.yaml()), "seed %s generated YAML should parse and compile", entry.Name())
		require.NoErrorf(t, exerciseFuzzJSONTemplateErr(candidate.json()), "seed %s generated JSON should parse and compile", entry.Name())
	}
}

func TestTemplateFromFuzzDataRejectsOversizeInput(t *testing.T) {
	data := make([]byte, fuzzMaxInputSize+1)
	require.False(t, fuzzTemplateParsing(data))
}

func TestFuzzTemplateHelperFileLoadingDisabled(t *testing.T) {
	options := newFuzzExecutorOptions()
	reader, err := options.Options.LoadHelperFile("anything.js", "fuzz-template.yaml", options.Catalog)
	require.Nil(t, reader)
	require.ErrorIs(t, err, errFuzzHelperDisabled)
}
