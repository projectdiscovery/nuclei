package extractors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractor_ExtractRegex(t *testing.T) {
	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: RegexExtractor}, Regex: []string{`([A-Z])\w+`}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	got := e.ExtractRegex("RegEx")
	require.Equal(t, map[string]struct{}{"RegEx": {}}, got)

	got = e.ExtractRegex("regex")
	require.Equal(t, map[string]struct{}{}, got)
}

func TestExtractor_ExtractKval(t *testing.T) {
	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: KValExtractor}, KVal: []string{"content_type"}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	got := e.ExtractKval(map[string]interface{}{"content_type": "text/html"})
	require.Equal(t, map[string]struct{}{"text/html": {}}, got)

	got = e.ExtractKval(map[string]interface{}{"authorization": "Basic YWxhZGRpbjpvcGVuc2VzYW1l"})
	require.Equal(t, map[string]struct{}{}, got)

}

func TestExtractor_ExtractXPath(t *testing.T) {
	body := `<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
`

	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"/html/body/div/p[2]/a"}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	got := e.ExtractXPath(body)
	require.Equal(t, map[string]struct{}{"More information...": {}}, got)

	e = &Extractor{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"/html/body/div/p[3]/a"}}
	got = e.ExtractXPath(body)
	require.Equal(t, map[string]struct{}{}, got)
}

func TestExtractor_ExtractJSON(t *testing.T) {
	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: JSONExtractor}, JSON: []string{".[] | .id"}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	got := e.ExtractJSON(`[{"id": 1}]`)
	require.Equal(t, map[string]struct{}{"1": {}}, got)

	got = e.ExtractJSON(`{"id": 1}`)
	require.Equal(t, map[string]struct{}{}, got)
}

func TestExtractor_ExtractDSL(t *testing.T) {
	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: DSLExtractor}, DSL: []string{"to_upper(hello)"}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	got := e.ExtractDSL(map[string]interface{}{"hello": "hi"})
	require.Equal(t, map[string]struct{}{"HI": {}}, got)

	got = e.ExtractDSL(map[string]interface{}{"hi": "hello"})
	require.Equal(t, map[string]struct{}{}, got)
}
