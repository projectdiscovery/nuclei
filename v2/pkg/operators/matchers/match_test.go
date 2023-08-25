package matchers

import (
	"testing"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/stretchr/testify/require"
)

func TestWordANDCondition(t *testing.T) {
	m := &Matcher{condition: ANDCondition, Words: []string{"a", "b"}}

	isMatched, matched := m.MatchWords("a b", nil)
	require.True(t, isMatched, "Could not match words with valid AND condition")
	require.Equal(t, m.Words, matched)

	isMatched, matched = m.MatchWords("b", nil)
	require.False(t, isMatched, "Could match words with invalid AND condition")
	require.Equal(t, []string{}, matched)
}

func TestRegexANDCondition(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "and", Regex: []string{"[a-z]{3}", "\\d{2}"}}
	err := m.CompileMatchers()
	require.Nil(t, err)

	isMatched, matched := m.MatchRegex("abc abcd 123")
	require.True(t, isMatched, "Could not match regex with valid AND condition")
	require.Equal(t, []string{"abc", "abc", "12"}, matched)

	isMatched, matched = m.MatchRegex("bc 1")
	require.False(t, isMatched, "Could match regex with invalid AND condition")
	require.Equal(t, []string{}, matched)
}

func TestORCondition(t *testing.T) {
	m := &Matcher{condition: ORCondition, Words: []string{"a", "b"}}

	isMatched, matched := m.MatchWords("a b", nil)
	require.True(t, isMatched, "Could not match valid word OR condition")
	require.Equal(t, []string{"a"}, matched)

	isMatched, matched = m.MatchWords("b", nil)
	require.True(t, isMatched, "Could not match valid word OR condition")
	require.Equal(t, []string{"b"}, matched)

	isMatched, matched = m.MatchWords("c", nil)
	require.False(t, isMatched, "Could match invalid word OR condition")
	require.Equal(t, []string{}, matched)
}

func TestRegexOrCondition(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "or", Regex: []string{"[a-z]{3}", "\\d{2}"}}
	err := m.CompileMatchers()
	require.Nil(t, err)

	isMatched, matched := m.MatchRegex("ab 123")
	require.True(t, isMatched, "Could not match valid regex OR condition")
	require.Equal(t, []string{"12"}, matched)

	isMatched, matched = m.MatchRegex("bc 1")
	require.False(t, isMatched, "Could match invalid regex OR condition")
	require.Equal(t, []string{}, matched)
}

func TestHexEncoding(t *testing.T) {
	m := &Matcher{Encoding: "hex", Type: MatcherTypeHolder{MatcherType: WordsMatcher}, Part: "body", Words: []string{"50494e47"}}
	err := m.CompileMatchers()
	require.Nil(t, err, "could not compile matcher")

	isMatched, matched := m.MatchWords("PING", nil)
	require.True(t, isMatched, "Could not match valid Hex condition")
	require.Equal(t, m.Words, matched)
}

func TestMatcher_MatchDSL(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("contains(body, \"{{VARIABLE}}\")", dsl.HelperFunctions)
	require.Nil(t, err, "couldn't compile expression")

	m := &Matcher{Type: MatcherTypeHolder{MatcherType: DSLMatcher}, dslCompiled: []*govaluate.EvaluableExpression{compiled}}
	err = m.CompileMatchers()
	require.Nil(t, err, "could not compile matcher")

	values := []string{"PING", "pong"}

	for value := range values {
		isMatched := m.MatchDSL(map[string]interface{}{"body": value, "VARIABLE": value})
		require.True(t, isMatched)
	}
}

func TestMatcher_MatchXPath_HTML(t *testing.T) {
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
	body2 := `<!doctype html>
<html>
<head>
    <title>Example Domain</title>
</head>
<body>
<h1> It's test time! </h1>
</body>
</html>
`

	// single match
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, XPath: []string{"/html/body/div/p[2]/a"}}
	err := m.CompileMatchers()
	require.Nil(t, err)

	isMatched := m.MatchXPath(body)
	require.True(t, isMatched, "Could not match valid XPath")

	isMatched = m.MatchXPath("<h1>aaaaaaaaa")
	require.False(t, isMatched, "Could match invalid XPath")

	// OR match
	m = &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, Condition: "or", XPath: []string{"/html/head/title[contains(text(), 'PATRICAAA')]", "/html/body/div/p[2]/a"}}
	err = m.CompileMatchers()
	require.Nil(t, err)

	isMatched = m.MatchXPath(body)
	require.True(t, isMatched, "Could not match valid multi-XPath with OR condition")

	isMatched = m.MatchXPath(body2)
	require.False(t, isMatched, "Could match invalid multi-XPath with OR condition")

	// AND match
	m = &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, Condition: "and", XPath: []string{"/html/head/title[contains(text(), 'Example Domain')]", "/html/body/div/p[2]/a"}}
	err = m.CompileMatchers()
	require.Nil(t, err)

	isMatched = m.MatchXPath(body)
	require.True(t, isMatched, "Could not match valid multi-XPath with AND condition")

	isMatched = m.MatchXPath(body2)
	require.False(t, isMatched, "Could match invalid multi-XPath with AND condition")

	// invalid xpath
	m = &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, XPath: []string{"//a[@a==1]"}}
	_ = m.CompileMatchers()
	isMatched = m.MatchXPath(body)
	require.False(t, isMatched, "Invalid xpath did not return false")
}

func TestMatcher_MatchXPath_XML(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?><foo>bar</foo><wibble id="1" /><parent><child>baz</child></parent>`
	body2 := `<?xml version="1.0" encoding="utf-8"?><test>bar</test><wibble2 id="1" /><roditelj><dijete>alo</dijete></roditelj>`

	// single match
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, XPath: []string{"//foo[contains(text(), 'bar')]"}}
	err := m.CompileMatchers()
	require.Nil(t, err)

	isMatched := m.MatchXPath(body)
	require.True(t, isMatched, "Could not match valid XPath")

	isMatched = m.MatchXPath("<h1>aaaaaaaaa</h1>")
	require.False(t, isMatched, "Could match invalid XPath")

	// OR match
	m = &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, Condition: "or", XPath: []string{"/foo[contains(text(), 'PATRICAAA')]", "/parent/child"}}
	err = m.CompileMatchers()
	require.Nil(t, err)

	isMatched = m.MatchXPath(body)
	require.True(t, isMatched, "Could not match valid multi-XPath with OR condition")

	isMatched = m.MatchXPath(body2)
	require.False(t, isMatched, "Could match invalid multi-XPath with OR condition")

	// AND match
	m = &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, Condition: "and", XPath: []string{"/foo[contains(text(), 'bar')]", "/parent/child"}}
	err = m.CompileMatchers()
	require.Nil(t, err)

	isMatched = m.MatchXPath(body)
	require.True(t, isMatched, "Could not match valid multi-XPath with AND condition")

	isMatched = m.MatchXPath(body2)
	require.False(t, isMatched, "Could match invalid multi-XPath with AND condition")

	// invalid xpath
	m = &Matcher{Type: MatcherTypeHolder{MatcherType: XPathMatcher}, XPath: []string{"//a[@a==1]"}}
	_ = m.CompileMatchers()
	isMatched = m.MatchXPath(body)
	require.False(t, isMatched, "Invalid xpath did not return false")

	// invalid xml
	isMatched = m.MatchXPath("<h1> not right <q id=2/>notvalid")
	require.False(t, isMatched, "Invalid xpath did not return false")
}
