package matchers

import (
	"bytes"
	"strings"
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

func TestMatchRegex_ScanCapAndPrefix(t *testing.T) {
	type tc struct {
		name     string
		regexes  []string
		corpus   string
		cond     string
		matchAll bool
		expectOK bool
		wantAny  string // "" means don't care
	}

	// Build a large string > maxRegexScanBytes
	large := bytes.Repeat([]byte{'x'}, maxRegexScanBytes+128)
	largeStr := string(large)

	tests := []tc{
		{
			name:     "prefix short-circuit: no prefix present",
			regexes:  []string{"abc.*def"},
			corpus:   largeStr, // no "abc" present
			cond:     "or",
			matchAll: false,
			expectOK: false,
		},
		{
			name:     "scan cap: match after cap not found",
			regexes:  []string{"Z+"},
			corpus:   largeStr + "ZZZ", // beyond cap
			cond:     "or",
			matchAll: false,
			expectOK: false,
		},
		{
			name:     "scan cap: match before cap found",
			regexes:  []string{"Z+"},
			corpus:   strings.Repeat("x", maxRegexScanBytes-10) + "ZZZ" + "TAIL",
			cond:     "or",
			matchAll: false,
			expectOK: true,
			wantAny:  "Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: tt.cond, MatchAll: tt.matchAll, Regex: tt.regexes}
			err := m.CompileMatchers()
			require.NoError(t, err)
			ok, got := m.MatchRegex(tt.corpus)
			require.Equal(t, tt.expectOK, ok)
			if tt.expectOK && tt.wantAny != "" {
				found := false
				for _, s := range got {
					if strings.Contains(s, tt.wantAny) {
						found = true
						break
					}
				}
				require.True(t, found, "expected any match containing %q in %v", tt.wantAny, got)
			}
		})
	}
}

// Benchmarks for visibility (not strict comparisons, but useful signals)
func benchmarkMatchRegex(b *testing.B, corpus string, regexes []string, cond string, matchAll bool) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: cond, MatchAll: matchAll, Regex: regexes}
	require.NoError(b, m.CompileMatchers())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.MatchRegex(corpus)
	}
}

func BenchmarkMatchRegex_NoPrefixInLargeBody(b *testing.B) {
	corpus := string(bytes.Repeat([]byte{'x'}, maxRegexScanBytes+256))
	benchmarkMatchRegex(b, corpus, []string{"abc.*def"}, "or", false)
}

func BenchmarkMatchRegex_PrefixPresent(b *testing.B) {
	corpus := strings.Repeat("x", 1024) + "abc" + strings.Repeat("y", 1024) + "def"
	benchmarkMatchRegex(b, corpus, []string{"abc.*def"}, "or", false)
}
