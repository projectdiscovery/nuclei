package matchers

import (
	"testing"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
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

	for _, value := range values {
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

func TestMatchRegex_CaseInsensitivePrefixSkip(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "or", Regex: []string{"(?i)abc"}}
	err := m.CompileMatchers()
	require.NoError(t, err)
	ok, got := m.MatchRegex("zzz AbC yyy")
	require.True(t, ok)
	require.NotEmpty(t, got)
}

func TestMatchStatusCodeAndSize(t *testing.T) {
	mStatus := &Matcher{Status: []int{200, 302}}
	require.True(t, mStatus.MatchStatusCode(200))
	require.True(t, mStatus.MatchStatusCode(302))
	require.False(t, mStatus.MatchStatusCode(404))

	mSize := &Matcher{Size: []int{5, 10}}
	require.True(t, mSize.MatchSize(5))
	require.False(t, mSize.MatchSize(7))
}

func TestMatchBinary_AND_OR(t *testing.T) {
	// AND should fail if any binary not present
	mAnd := &Matcher{Type: MatcherTypeHolder{MatcherType: BinaryMatcher}, Condition: "and", Binary: []string{"50494e47", "414141"}} // "PING", "AAA"
	require.NoError(t, mAnd.CompileMatchers())
	ok, _ := mAnd.MatchBinary("PING")
	require.False(t, ok)
	// OR should succeed if any present
	mOr := &Matcher{Type: MatcherTypeHolder{MatcherType: BinaryMatcher}, Condition: "or", Binary: []string{"414141", "50494e47"}} // "AAA", "PING"
	require.NoError(t, mOr.CompileMatchers())
	ok, got := mOr.MatchBinary("xxPINGyy")
	require.True(t, ok)
	require.NotEmpty(t, got)
}

func TestMatchRegex_LiteralPrefixShortCircuit(t *testing.T) {
	// AND: first regex has literal prefix "abc"; corpus lacks it => early false
	mAnd := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "and", Regex: []string{"abc[0-9]*", "[0-9]{2}"}}
	require.NoError(t, mAnd.CompileMatchers())
	ok, matches := mAnd.MatchRegex("zzz 12 yyy")
	require.False(t, ok)
	require.Empty(t, matches)

	// OR: first regex skipped due to missing prefix, second matches => true
	mOr := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "or", Regex: []string{"abc[0-9]*", "[0-9]{2}"}}
	require.NoError(t, mOr.CompileMatchers())
	ok, matches = mOr.MatchRegex("zzz 12 yyy")
	require.True(t, ok)
	require.Equal(t, []string{"12"}, matches)
}

func TestMatcher_MatchDSL_ErrorHandling(t *testing.T) {
	// First expression errors (division by zero), second is true
	bad, err := govaluate.NewEvaluableExpression("1 / 0")
	require.NoError(t, err)
	good, err := govaluate.NewEvaluableExpression("1 == 1")
	require.NoError(t, err)

	m := &Matcher{Type: MatcherTypeHolder{MatcherType: DSLMatcher}, Condition: "or", dslCompiled: []*govaluate.EvaluableExpression{bad, good}}
	require.NoError(t, m.CompileMatchers())
	ok := m.MatchDSL(map[string]interface{}{})
	require.True(t, ok)
}
