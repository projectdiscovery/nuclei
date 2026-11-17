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

// TestExtractor_ExtractXPath_XMLPrologHTMLFallback mirrors the matcher case for
// extractors: an XHTML document that declares itself as XML must still be
// extracted from instead of yielding no values.
func TestExtractor_ExtractXPath_XMLPrologHTMLFallback(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>a&nbsp;b</title></head>
<body><h1 id="h">Admin</h1><br></body>
</html>`

	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"//h1"}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	got := e.ExtractXPath(body)
	require.Equal(t, map[string]struct{}{"Admin": {}}, got)

	// The XML-only entry point is unchanged: a document that is not well-formed
	// XML yields no results.
	require.Equal(t, map[string]struct{}{}, e.ExtractXML(body))
}

// TestExtractor_ExtractXPath_XMLPrologNoFallbackOnMiss guards the extractor
// fallback the same way as the matcher one.
func TestExtractor_ExtractXPath_XMLPrologNoFallbackOnMiss(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?><Root><Item>x</Item></Root>`

	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"//item"}}
	err := e.CompileExtractors()
	require.Nil(t, err)

	require.Equal(t, map[string]struct{}{}, e.ExtractXPath(body), "Well-formed XML must be matched case-sensitively")

	e = &Extractor{Type: ExtractorTypeHolder{ExtractorType: XPathExtractor}, XPath: []string{"//Item"}}
	err = e.CompileExtractors()
	require.Nil(t, err)

	require.Equal(t, map[string]struct{}{"x": {}}, e.ExtractXPath(body))
}
