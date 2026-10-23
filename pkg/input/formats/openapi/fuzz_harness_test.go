package openapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFuzzOpenAPIParsingSeedCorpus(t *testing.T) {
	entries, err := os.ReadDir("testdata/gofuzz-corpus")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join("testdata/gofuzz-corpus", entry.Name()))
		require.NoError(t, err)
		require.Truef(t, fuzzOpenAPIParsing(data), "seed %s should produce at least one request", entry.Name())
	}
}

func TestFuzzOpenAPIParsingRejectsOversizeInput(t *testing.T) {
	require.False(t, fuzzOpenAPIParsing(make([]byte, fuzzMaxInputSize+1)))
}

// Null entries decode to nil pointers and used to panic during request
// generation. The remaining valid entries must still produce requests.
func TestFuzzOpenAPIParsingNullEntries(t *testing.T) {
	specs := map[string]string{
		"null server": `
openapi: 3.0.0
info: {title: t, version: "1"}
servers:
  -
  - {url: "http://example.com"}
paths:
  /users:
    get:
      responses: {"200": {description: ok}}
`,
		"null media type": `
openapi: 3.0.0
info: {title: t, version: "1"}
servers: [{url: "http://example.com"}]
paths:
  /users:
    post:
      requestBody:
        content:
          application/xml:
          application/json:
            schema: {type: object, properties: {name: {type: string}}}
      responses: {"200": {description: ok}}
`,
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			require.True(t, fuzzOpenAPIParsing([]byte(spec)))
		})
	}
}
