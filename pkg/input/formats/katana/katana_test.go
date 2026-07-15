package katana

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestKatanaFormatName(t *testing.T) {
	require.Equal(t, "katana", New().Name())
}

func TestKatanaFormatParse(t *testing.T) {
	inputFile := "../testdata/katana.jsonl"

	file, err := os.Open(inputFile)
	require.Nilf(t, err, "error opening katana input file: %v", err)
	defer func() { _ = file.Close() }()

	var got []*types.RequestResponse
	err = New().Parse(file, func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, inputFile)
	require.NoError(t, err)

	// 3 JSONL records + 1 bare URL line; malformed and blank lines skipped.
	require.Len(t, got, 4)

	urls := make([]string, 0, len(got))
	for _, rr := range got {
		urls = append(urls, rr.URL.String())
	}
	require.ElementsMatch(t, []string{
		"https://ginandjuice.shop/catalog/product?productId=1",
		"https://ginandjuice.shop/catalog/subscribe",
		"https://ginandjuice.shop/login",
		"https://ginandjuice.shop/about",
	}, urls)
}

func TestKatanaFormatRawRequestPreserved(t *testing.T) {
	// A POST with a captured raw request must preserve method and body.
	rr := parseSingle(t, `{"request":{"method":"POST","endpoint":"https://example.com/sub","raw":"POST /sub HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b.com"}}`)
	require.Equal(t, "POST", rr.Request.Method)
	require.Equal(t, "email=a%40b.com", rr.Request.Body)
	require.Equal(t, "https://example.com/sub", rr.URL.String())
}

func TestKatanaFormatComponentSynthesis(t *testing.T) {
	// No raw request: it must be synthesized from method/endpoint/headers/body.
	rr := parseSingle(t, `{"request":{"method":"POST","endpoint":"https://example.com/login","headers":{"Content-Type":"application/json"},"body":"{\"u\":\"admin\"}"}}`)
	require.Equal(t, "POST", rr.Request.Method)
	require.Equal(t, `{"u":"admin"}`, rr.Request.Body)
	require.Equal(t, "https://example.com/login", rr.URL.String())

	built, err := rr.BuildRequest()
	require.NoError(t, err)
	require.Equal(t, "application/json", built.Header.Get("Content-Type"))
	require.Equal(t, "example.com", built.Host)
}

func TestKatanaFormatQueryParamsRetained(t *testing.T) {
	// Parameter variants must survive so the fuzzer can target them.
	rr := parseSingle(t, `{"request":{"method":"GET","endpoint":"https://example.com/p?id=1&q=2"}}`)
	require.Equal(t, "https://example.com/p?id=1&q=2", rr.URL.String())
	require.Equal(t, "GET", rr.Request.Method)
}

func TestKatanaFormatGracefulSkips(t *testing.T) {
	input := strings.Join([]string{
		"",
		"garbage",
		`{"request":null}`,
		`{"request":{"endpoint":""}}`,
		`{"request":{"method":"GET","endpoint":"https://example.com/ok"}}`,
	}, "\n")

	var got []*types.RequestResponse
	err := New().Parse(strings.NewReader(input), func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, "test")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "https://example.com/ok", got[0].URL.String())
}

func TestKatanaFormatCallbackStops(t *testing.T) {
	input := strings.Join([]string{
		`{"request":{"method":"GET","endpoint":"https://example.com/1"}}`,
		`{"request":{"method":"GET","endpoint":"https://example.com/2"}}`,
	}, "\n")

	var count int
	err := New().Parse(strings.NewReader(input), func(_ *types.RequestResponse) bool {
		count++
		return true // request to stop after the first
	}, "test")
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func parseSingle(t *testing.T, line string) *types.RequestResponse {
	t.Helper()
	var got *types.RequestResponse
	err := New().Parse(strings.NewReader(line), func(rr *types.RequestResponse) bool {
		got = rr
		return false
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, got)
	return got
}
