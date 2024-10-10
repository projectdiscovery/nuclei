package dataformat

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	graphqlQueryWithInlineArgs = `{
		"query": "\n                    query {\n                        jobs(jobType: \"front-end\") {\n                            id\n                            name\n                            type\n                            description\n                        }\n                    }\n                "
	  }`

	graphqlQueryWithVariables = `{
  "query": "mutation ImportPaste ($host: String!, $port: Int!, $path: String!, $scheme: String!) {\n        importPaste(host: $host, port: $port, path: $path, scheme: $scheme) {\n          result\n        }\n      }",
  "variables": {
    "host": "example.com",
    "port": 80,
    "path": "/robots.txt",
    "scheme": "http"
  }
}`
)

func Test_GraphQL_IsGraphQL(t *testing.T) {
	graphql := NewGraphql()
	require.True(
		t,
		graphql.IsType(graphqlQueryWithInlineArgs),
		"expected query to be detected as graphql",
	)
	require.False(
		t,
		graphql.IsType("not a graphql query"),
		"expected query to not be detected as graphql",
	)
	require.False(
		t,
		graphql.IsType(`{"query": "not a graphql query"}`),
		"expected query to not be detected as graphql",
	)
}

func Test_GraphQL_DecodeEncode_InlineArgs(t *testing.T) {
	decodeQueryGetKV := func(query string) (KV, map[string]interface{}, *Graphql) {
		graphql := NewGraphql()

		decoded, err := graphql.Decode(query)
		require.Nil(t, err, "could not decode graphql query")

		keyValues := make(map[string]interface{})
		decoded.Iterate(func(key string, value interface{}) bool {
			if strings.HasPrefix(key, "#_") {
				return true
			}
			keyValues[key] = value
			return true
		})
		return decoded, keyValues, graphql
	}

	// Test decoding and encoding
	t.Run("inline args with variables", func(t *testing.T) {
		decoded, keyValues, graphql := decodeQueryGetKV(graphqlQueryWithVariables)
		require.Equal(t, map[string]interface{}{
			"host":   "example.com",
			"port":   float64(80),
			"path":   "/robots.txt",
			"scheme": "http",
		}, keyValues)

		decoded.Set("path", "/robots.txt; cat /etc/passwd")

		// Test encoding
		encoded, err := graphql.Encode(decoded)
		require.Nil(t, err, "could not encode graphql query")

		_, newKeyValues, _ := decodeQueryGetKV(encoded)
		require.Equal(t, "/robots.txt; cat /etc/passwd", newKeyValues["path"])

		// Try to write non-string paths as well
		t.Run("non-string paths", func(t *testing.T) {
			decoded.Set("port", "80; cat /etc/passwd")
			encoded, err = graphql.Encode(decoded)
			require.Nil(t, err, "could not encode graphql query")

			_, newKeyValues, _ = decodeQueryGetKV(encoded)
			require.Equal(t, "80; cat /etc/passwd", newKeyValues["port"])
		})
	})

	t.Run("inline args", func(t *testing.T) {
		decoded, keyValues, graphql := decodeQueryGetKV(graphqlQueryWithInlineArgs)
		require.Equal(t, map[string]interface{}{
			"jobType": "front-end",
		}, keyValues)

		decoded.Set("jobType", "canary")

		// Test encoding
		encoded, err := graphql.Encode(decoded)
		require.Nil(t, err, "could not encode graphql query")

		_, newKeyValues, _ := decodeQueryGetKV(encoded)
		require.Equal(t, map[string]interface{}{
			"jobType": "canary",
		}, newKeyValues)
	})

}
