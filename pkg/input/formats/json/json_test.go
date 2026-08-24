package json

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

var expectedURLs = []string{
	"https://ginandjuice.shop/",
	"https://ginandjuice.shop/catalog/product?productId=1",
	"https://ginandjuice.shop/resources/js/stockCheck.js",
	"https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js",
	"https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js",
	"https://ginandjuice.shop/resources/js/stockCheck.js",
	"https://ginandjuice.shop/catalog/product/stock",
	"https://ginandjuice.shop/catalog/cart",
	"https://ginandjuice.shop/catalog/product?productId=1",
	"https://ginandjuice.shop/catalog/subscribe",
	"https://ginandjuice.shop/blog",
	"https://ginandjuice.shop/blog/?search=dadad&back=%2Fblog%2F",
	"https://ginandjuice.shop/logger",
	"https://ginandjuice.shop/blog/",
	"https://ginandjuice.shop/blog/post?postId=3",
	"https://ginandjuice.shop/about",
	"https://ginandjuice.shop/my-account",
	"https://ginandjuice.shop/login",
	"https://ginandjuice.shop/login",
	"https://ginandjuice.shop/login",
	"https://ginandjuice.shop/my-account",
	"https://ginandjuice.shop/catalog/cart",
	"https://ginandjuice.shop/my-account",
	"https://ginandjuice.shop/logout",
	"https://ginandjuice.shop/",
	"https://ginandjuice.shop/catalog",
}

func TestJSONFormatterParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/ginandjuice.proxify.json"

	file, err := os.Open(proxifyInputFile)
	require.Nilf(t, err, "error opening proxify input file: %v", err)
	defer func() {
		_ = file.Close()
	}()

	var urls []string
	err = format.Parse(file, func(request *types.RequestResponse) bool {
		urls = append(urls, request.URL.String())
		return false
	}, proxifyInputFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(urls) != len(expectedURLs) {
		t.Fatalf("invalid number of urls: %d", len(urls))
	}
	require.ElementsMatch(t, urls, expectedURLs)
}

func TestJSONFormatterParseTargetRecords(t *testing.T) {
	const input = `{"url":"https://one.example","tags":[" Apache ","apache","Shiro"],"exclude-tags":[],"severity":["HIGH"],"templates":[" cves/2026/ "]}
{"url":"https://two.example"}
`

	var inputs []*contextargs.MetaInput
	err := New().ParseMeta(strings.NewReader(input), func(input *contextargs.MetaInput) bool {
		inputs = append(inputs, input)
		return true
	}, "")
	require.NoError(t, err)
	require.Len(t, inputs, 2)

	first := inputs[0]
	require.Equal(t, "https://one.example", first.Input)
	require.True(t, first.TargetFilter.HasTags)
	require.True(t, first.TargetFilter.HasExcludeTags)
	require.True(t, first.TargetFilter.HasSeverities)
	require.True(t, first.TargetFilter.HasTemplates)
	require.Equal(t, []string{"apache", "shiro"}, first.TargetFilter.Tags)
	require.Empty(t, first.TargetFilter.ExcludeTags)
	require.Equal(t, "high", first.TargetFilter.Severities.String())
	require.Equal(t, []string{"cves/2026/"}, first.TargetFilter.Templates)

	second := inputs[1]
	require.Equal(t, "https://two.example", second.Input)
	require.False(t, second.TargetFilter.HasTags)
	require.False(t, second.TargetFilter.HasExcludeTags)
	require.False(t, second.TargetFilter.HasSeverities)
	require.False(t, second.TargetFilter.HasTemplates)
}

func TestJSONFormatterTreatsSeverityAsLiteralValue(t *testing.T) {
	previousWorkingDirectory, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() {
		require.NoError(t, os.Chdir(previousWorkingDirectory))
	})
	require.NoError(t, os.WriteFile("high", []byte("critical\n"), 0o600))

	const input = `{"url":"https://example.com","severity":["high"]}`
	var parsed *contextargs.MetaInput
	err = New().ParseMeta(strings.NewReader(input), func(input *contextargs.MetaInput) bool {
		parsed = input
		return true
	}, "")

	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, "high", parsed.TargetFilter.Severities.String())
}

func TestJSONFormatterParseTargetValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		message string
	}{
		{name: "missing URL", input: `{"tags":["apache"]}`, message: `field "url" is required`},
		{name: "empty URL", input: `{"url":" "}`, message: `field "url" is required`},
		{name: "null field", input: `{"url":"https://example.com","tags":null}`, message: `field "tags" must not be null`},
		{name: "unknown field", input: `{"url":"https://example.com","unknown":true}`, message: `unknown field "unknown"`},
		{name: "request is not a target field", input: `{"url":"https://example.com","request":{}}`, message: `unknown field "request"`},
		{name: "wrong tags type", input: `{"url":"https://example.com","tags":"apache"}`, message: `cannot unmarshal string`},
		{name: "empty list value", input: `{"url":"https://example.com","tags":[""]}`, message: `contains an empty value`},
		{name: "invalid severity", input: `{"url":"https://example.com","severity":["urgent"]}`, message: `invalid severity "urgent"`},
		{name: "not an object", input: `["https://example.com"]`, message: `each record must be a JSON object`},
		{name: "malformed JSON", input: "{\n", message: `jsonl line 1: invalid JSON`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := New().ParseMeta(strings.NewReader(test.input), func(*contextargs.MetaInput) bool {
				return true
			}, "")
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestJSONFormatterParseMetaStopsOnCallback(t *testing.T) {
	const input = `{"url":"https://one.example"}
{"url":"https://two.example"}
`
	count := 0
	err := New().ParseMeta(strings.NewReader(input), func(*contextargs.MetaInput) bool {
		count++
		return false
	}, "")
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestJSONFormatterParseMetaRejectsMixedRecords(t *testing.T) {
	const input = `{"url":"https://one.example"}
{"url":"https://two.example","request":{"raw":"GET / HTTP/1.1\r\nHost: two.example\r\n\r\n"}}
`
	err := New().ParseMeta(strings.NewReader(input), func(*contextargs.MetaInput) bool {
		return true
	}, "")
	require.ErrorContains(t, err, "cannot mix target and proxify records")
}

func TestJSONFormatterParseMetaRejectsHybridProxifyRecord(t *testing.T) {
	const input = `{"url":"https://example.com","tags":["apache"],"request":{"raw":"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}}`
	err := New().ParseMeta(strings.NewReader(input), func(*contextargs.MetaInput) bool {
		return true
	}, "")
	require.ErrorContains(t, err, `jsonl line 1: Proxify request records cannot include target filter field "tags"`)
}

func TestJSONFormatterReportsRecordLineNumbers(t *testing.T) {
	const input = `{"url":"https://one.example"}

{"url":"https://two.example","unknown":true}
`
	err := New().ParseMeta(strings.NewReader(input), func(*contextargs.MetaInput) bool {
		return true
	}, "")
	require.ErrorContains(t, err, `jsonl line 3: invalid target record`)
}

func TestJSONFormatterParseMetaPreservesMultilineProxifyInput(t *testing.T) {
	const input = `{
  "url": "https://example.com/",
  "request": {
    "raw": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
  }
}`
	var inputs []*contextargs.MetaInput
	err := New().ParseMeta(strings.NewReader(input), func(input *contextargs.MetaInput) bool {
		inputs = append(inputs, input)
		return true
	}, "")
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Equal(t, "https://example.com/", inputs[0].Input)
	require.NotNil(t, inputs[0].ReqResp)
	require.Nil(t, inputs[0].TargetFilter)
}
