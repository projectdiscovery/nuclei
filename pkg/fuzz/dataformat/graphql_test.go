package dataformat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	graphqlInlineArgsBody = `{
		"query": "query { jobs(jobType: \"front-end\") { id name } }"
	}`

	graphqlVariablesBody = `{
  "query": "mutation ImportPaste($host: String!, $port: Int!, $path: String!, $scheme: String!) { importPaste(host: $host, port: $port, path: $path, scheme: $scheme) { result } }",
  "variables": {
    "host": "example.com",
    "port": 80,
    "path": "/robots.txt",
    "scheme": "http"
  }
}`

	graphqlNestedVariablesBody = `{
  "query": "mutation ($input: ImportInput!) { importPaste(input: $input) { result } }",
  "operationName": "Import",
  "variables": {
    "input": {
      "host": "example.com",
      "path": "/robots.txt"
    }
  }
}`
)

func fuzzableKV(t *testing.T, decoded KV) map[string]any {
	t.Helper()
	out := make(map[string]any)
	decoded.Iterate(func(key string, value any) bool {
		if strings.HasPrefix(key, "#_") {
			return true
		}
		out[key] = value
		return true
	})
	return out
}

func TestGraphqlIsType(t *testing.T) {
	g := NewGraphql()

	require.True(t, g.IsType(graphqlInlineArgsBody))
	require.True(t, g.IsType(graphqlVariablesBody))
	require.False(t, g.IsType("not-json"))
	require.False(t, g.IsType(`{"foo":"bar"}`))
	require.False(t, g.IsType(`{"query":"not a graphql query"}`))
	require.False(t, g.IsType(`{"variables":{"host":"example.com"}}`))
}

func TestGraphqlDecodeEncodeVariables(t *testing.T) {
	g := NewGraphql()

	decoded, err := g.Decode(graphqlVariablesBody)
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"host":   "example.com",
		"port":   float64(80),
		"path":   "/robots.txt",
		"scheme": "http",
	}, fuzzableKV(t, decoded))

	decoded.Set("path", "/robots.txt; cat /etc/passwd")
	encoded, err := g.Encode(decoded)
	require.NoError(t, err)

	roundTrip, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, "/robots.txt; cat /etc/passwd", fuzzableKV(t, roundTrip)["path"])
	require.Contains(t, encoded, `"variables"`)
	require.Contains(t, encoded, `/robots.txt; cat /etc/passwd`)
	// Injection stays in variables JSON, query text still references $path only.
	require.Contains(t, encoded, `path: $path`)
	require.NotContains(t, encoded, `path: "/robots.txt; cat /etc/passwd"`)
}

func TestGraphqlDecodeEncodeEmptyVariables(t *testing.T) {
	g := NewGraphql()
	body := `{
		"query": "query Lookup($input: String) { lookup(input: $input) { id } }",
		"variables": {}
	}`

	decoded, err := g.Decode(body)
	require.NoError(t, err)
	require.Empty(t, fuzzableKV(t, decoded))
	require.Equal(t, true, decoded.Get(graphqlMetaHasVariables))

	encoded, err := g.Encode(decoded)
	require.NoError(t, err)
	require.Contains(t, encoded, `"variables":{}`)
	require.Contains(t, encoded, `input: $input`)
	require.NotContains(t, encoded, `input: ""`)

	roundTrip, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, true, roundTrip.Get(graphqlMetaHasVariables))
	require.Empty(t, fuzzableKV(t, roundTrip))
}

func TestGraphqlDecodeEncodeInlineArgs(t *testing.T) {
	g := NewGraphql()

	decoded, err := g.Decode(graphqlInlineArgsBody)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"jobType": "front-end"}, fuzzableKV(t, decoded))

	decoded.Set("jobType", "canary-payload")
	encoded, err := g.Encode(decoded)
	require.NoError(t, err)

	roundTrip, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"jobType": "canary-payload"}, fuzzableKV(t, roundTrip))
	require.Contains(t, encoded, "canary-payload")
}

func TestGraphqlDecodeEncodeNullLiteral(t *testing.T) {
	g := NewGraphql()
	body := `{"query":"query { jobs(filter: null, nested: {value: null}) { id } }"}`

	decoded, err := g.Decode(body)
	require.NoError(t, err)
	require.Contains(t, fuzzableKV(t, decoded), "filter")
	require.Nil(t, decoded.Get("filter"))

	encoded, err := g.Encode(decoded)
	require.NoError(t, err)
	require.Contains(t, encoded, "filter: null")
	require.Contains(t, encoded, "nested: {value: null}")

	roundTrip, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Contains(t, fuzzableKV(t, roundTrip), "filter")
	require.Nil(t, roundTrip.Get("filter"))
}

func TestGraphqlInlineArgsPreserveDefaultedVariable(t *testing.T) {
	g := NewGraphql()
	body := `{"query":"query Jobs($limit: Int = 10) { jobs(limit: $limit, status: ACTIVE) { id } }"}`

	decoded, err := g.Decode(body)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"status": "ACTIVE"}, fuzzableKV(t, decoded))

	decoded.Set("status", "PAUSED")
	encoded, err := g.Encode(decoded)
	require.NoError(t, err)
	require.Contains(t, encoded, "$limit: Int = 10")
	require.Contains(t, encoded, "limit: $limit")
	require.Contains(t, encoded, "status: PAUSED")

	roundTrip, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"status": "PAUSED"}, fuzzableKV(t, roundTrip))
}

func TestGraphqlDecodeEncodePreservesExtensions(t *testing.T) {
	g := NewGraphql()
	body := `{"query":"query { viewer { id } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}`

	decoded, err := g.Decode(body)
	require.NoError(t, err)

	encoded, err := g.Encode(decoded)
	require.NoError(t, err)

	var roundTrip map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &roundTrip))
	require.Equal(t, map[string]any{
		"persistedQuery": map[string]any{
			"version":    float64(1),
			"sha256Hash": "abc123",
		},
	}, roundTrip["extensions"])
}

func TestGraphqlInlineArgumentKeysIdentifyLocations(t *testing.T) {
	g := NewGraphql()
	body := `{"query":"query { users(first: 10) { id } posts(first: 20) { id } }"}`

	decoded, err := g.Decode(body)
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"users.first": "10",
		"posts.first": "20",
	}, fuzzableKV(t, decoded))

	decoded.Set("users.first", "99")
	encoded, err := g.Encode(decoded)
	require.NoError(t, err)
	require.Contains(t, encoded, "users(first: 99)")
	require.Contains(t, encoded, "posts(first: 20)")

	roundTrip, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, "99", roundTrip.Get("users.first"))
	require.Equal(t, "20", roundTrip.Get("posts.first"))
}

func TestGraphqlInlineArgumentsPreserveLiteralTypes(t *testing.T) {
	g := NewGraphql()
	body := `{"query":"query { jobs(name: \"example\", status: ACTIVE, limit: 10, ratio: 1.5, flags: [ACTIVE, PAUSED], filter: {retries: 3, state: READY}) { id } }"}`

	decoded, err := g.Decode(body)
	require.NoError(t, err)
	decoded.Set("name", "canary")

	flags, ok := decoded.Get("flags").([]any)
	require.True(t, ok)
	flags[0] = "DISABLED"
	decoded.Set("flags", flags)

	filter, ok := decoded.Get("filter").(map[string]any)
	require.True(t, ok)
	filter["retries"] = "4"
	decoded.Set("filter", filter)

	encoded, err := g.Encode(decoded)
	require.NoError(t, err)
	require.Contains(t, encoded, `name: \"canary\"`)
	require.Contains(t, encoded, "status: ACTIVE")
	require.Contains(t, encoded, "limit: 10")
	require.Contains(t, encoded, "ratio: 1.5")
	require.Contains(t, encoded, "flags: [DISABLED, PAUSED]")
	require.Contains(t, encoded, "filter: {retries: 4, state: READY}")
	require.NotContains(t, encoded, `status: \"ACTIVE\"`)
	require.NotContains(t, encoded, `limit: \"10\"`)
}

func TestGraphqlDecodeEncodeNestedVariables(t *testing.T) {
	g := NewGraphql()

	decoded, err := g.Decode(graphqlNestedVariablesBody)
	require.NoError(t, err)
	require.Equal(t, "Import", decoded.Get(graphqlMetaOperationName))

	input, ok := fuzzableKV(t, decoded)["input"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "example.com", input["host"])
	require.Equal(t, "/robots.txt", input["path"])

	input["path"] = "/robots.txt' OR 1=1--"
	decoded.Set("input", input)

	encoded, err := g.Encode(decoded)
	require.NoError(t, err)
	require.Contains(t, encoded, `/robots.txt' OR 1=1--`)
	require.Contains(t, encoded, `"operationName":"Import"`)
}

func TestGraphqlDoesNotTreatRegularJSONAsGraphql(t *testing.T) {
	decoded, err := Decode(`{"foo":"bar","query":123}`)
	require.NoError(t, err)
	require.NotNil(t, decoded)
	require.Equal(t, JSONDataFormat, decoded.DataFormat)
}

func TestGraphqlPreferredOverJSONInDecode(t *testing.T) {
	decoded, err := Decode(graphqlVariablesBody)
	require.NoError(t, err)
	require.NotNil(t, decoded)
	require.Equal(t, GraphqlDataFormat, decoded.DataFormat)
	require.Equal(t, "example.com", decoded.Data.Get("host"))
}

func TestGraphqlEncodeRoundTripPreservesQueryWhenFuzzingVariables(t *testing.T) {
	g := NewGraphql()
	decoded, err := g.Decode(graphqlVariablesBody)
	require.NoError(t, err)

	originalQuery := decoded.Get(graphqlMetaQuery)
	decoded.Set("host", "evil.example")
	encoded, err := g.Encode(decoded)
	require.NoError(t, err)

	again, err := g.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, originalQuery, again.Get(graphqlMetaQuery))
	require.Equal(t, "evil.example", again.Get("host"))
}
