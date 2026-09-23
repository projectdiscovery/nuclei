package extractors

import (
	"regexp"
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

func TestExtractor_CompileRejectsNegativeRegexGroup(t *testing.T) {
	e := &Extractor{
		Type:       ExtractorTypeHolder{ExtractorType: RegexExtractor},
		Regex:      []string{`([A-Z])\w+`},
		RegexGroup: -1,
	}
	err := e.CompileExtractors()
	require.ErrorContains(t, err, "group must be >= 0")
}

func TestExtractor_CompileRejectsOutOfRangeRegexGroup(t *testing.T) {
	// A group beyond what the pattern captures can never match:
	// FindAllStringSubmatch returns NumSubexp()+1 entries, so ExtractRegex
	// skips every submatch and yields nothing. Before this check the template
	// compiled and ran, and an empty result was indistinguishable from "the
	// pattern didn't match the target".
	e := &Extractor{
		Type:       ExtractorTypeHolder{ExtractorType: RegexExtractor},
		Regex:      []string{`(\d+)`},
		RegexGroup: 5,
	}
	err := e.CompileExtractors()
	require.ErrorContains(t, err, "out of range")
	require.ErrorContains(t, err, "1 capture group")
}

func TestExtractor_CompileAcceptsInRangeRegexGroup(t *testing.T) {
	e := &Extractor{
		Type:       ExtractorTypeHolder{ExtractorType: RegexExtractor},
		Regex:      []string{`(\w+)@(\w+)`},
		RegexGroup: 2,
	}
	require.NoError(t, e.CompileExtractors())
	require.Equal(t, map[string]struct{}{"example": {}}, e.ExtractRegex("user@example"))
}

func TestExtractor_CompileValidatesGroupOnCachedRegex(t *testing.T) {
	// The compile path short-circuits on a cache hit. Validating only the
	// freshly-compiled branch would let the same pattern pass unchecked once
	// any other template had already compiled it.
	pattern := `(?:cached)-(\d+)-marker`

	warm := &Extractor{
		Type:  ExtractorTypeHolder{ExtractorType: RegexExtractor},
		Regex: []string{pattern},
	}
	require.NoError(t, warm.CompileExtractors())

	reuse := &Extractor{
		Type:       ExtractorTypeHolder{ExtractorType: RegexExtractor},
		Regex:      []string{pattern},
		RegexGroup: 4,
	}
	require.ErrorContains(t, reuse.CompileExtractors(), "out of range")
}

func TestExtractor_ExtractRegexNegativeGroupDoesNotPanic(t *testing.T) {
	// Defense in depth: even if an extractor is built programmatically (or
	// otherwise ends up with compiled regexes) without compilation-time checks,
	// extraction should not panic.
	compiled := regexp.MustCompile(`([A-Z])\w+`)
	e := &Extractor{
		RegexGroup: -1,
		regexCompiled: []*regexp.Regexp{
			compiled,
		},
	}

	require.NotPanics(t, func() {
		got := e.ExtractRegex("RegEx")
		require.Equal(t, map[string]struct{}{}, got)
	})
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
