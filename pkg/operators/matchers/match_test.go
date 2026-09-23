package matchers

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/stretchr/testify/require"
)

func withMatcherTestHelperFunction(t *testing.T, name string, fn govaluate.ExpressionFunction) {
	t.Helper()

	originalFn, hadFn := dsl.HelperFunctions[name]
	dsl.HelperFunctions[name] = fn
	t.Cleanup(func() {
		if hadFn {
			dsl.HelperFunctions[name] = originalFn
			return
		}
		delete(dsl.HelperFunctions, name)
	})
}

func mustCompileDSLMatcher(t *testing.T, expression string) *Matcher {
	t.Helper()

	matcher := &Matcher{
		Type: MatcherTypeHolder{MatcherType: DSLMatcher},
		DSL:  []string{expression},
	}
	require.NoError(t, matcher.CompileMatchers())
	return matcher
}

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
	m := mustCompileDSLMatcher(t, `contains(body, "{{VARIABLE}}")`)

	values := []string{"PING", "pong"}

	for _, value := range values {
		isMatched := m.MatchDSL(map[string]interface{}{"body": value, "VARIABLE": value})
		require.True(t, isMatched)
	}
}

func TestMatcherMatchDSLDoesNotExecuteHelpersFromResolvedValues(t *testing.T) {
	var waitForCalls int
	withMatcherTestHelperFunction(t, "wait_for", func(args ...interface{}) (interface{}, error) {
		waitForCalls++
		return true, nil
	})

	items := []struct {
		name       string
		expression string
		value      string
	}{
		{
			name:       "single quoted placeholder",
			expression: "contains(body, '{{server_token}}')",
			value:      "') && wait_for(5) && contains(body, '",
		},
		{
			name:       "double quoted placeholder",
			expression: `contains(body, "{{server_token}}")`,
			value:      `") && wait_for(5) && contains(body, "`,
		},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			matcher := mustCompileDSLMatcher(t, item.expression)

			require.False(t, matcher.MatchDSL(map[string]interface{}{
				"template-id":  "test-template",
				"body":         "safe body",
				"server_token": item.value,
			}))
			require.Zero(t, waitForCalls)
		})
	}
}

func TestMatcherMatchDSLMatchesResolvedValuesLiterally(t *testing.T) {
	var waitForCalls int
	withMatcherTestHelperFunction(t, "wait_for", func(args ...interface{}) (interface{}, error) {
		waitForCalls++
		return true, nil
	})

	items := []struct {
		name       string
		expression string
		value      string
	}{
		{
			name:       "single quoted placeholder",
			expression: "contains(body, '{{server_token}}')",
			value:      "') && wait_for(5) && contains(body, '",
		},
		{
			name:       "double quoted placeholder",
			expression: `contains(body, "{{server_token}}")`,
			value:      `") && wait_for(5) && contains(body, "`,
		},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			matcher := mustCompileDSLMatcher(t, item.expression)

			require.True(t, matcher.MatchDSL(map[string]interface{}{
				"template-id":  "test-template",
				"body":         "prefix " + item.value + " suffix",
				"server_token": item.value,
			}))
			require.Zero(t, waitForCalls)
		})
	}
}

func TestMatcherMatchDSLResolvedValuesPreserveBytes(t *testing.T) {
	items := []struct {
		name  string
		value string
	}{
		{
			name:  "newline",
			value: "a\nb",
		},
		{
			name:  "tab",
			value: "a\tb",
		},
		{
			name:  "carriage return",
			value: "a\rb",
		},
		{
			name:  "backslash",
			value: `a\b`,
		},
		{
			name:  "single quote",
			value: "a'b",
		},
		{
			name:  "double quote",
			value: `a"b`,
		},
		{
			name:  "mixed quotes and controls",
			value: "a\nb\tc\rd\\e'f\"g",
		},
	}

	expressions := []struct {
		name       string
		expression string
	}{
		{
			name:       "single quoted placeholder",
			expression: "contains(body, '{{server_token}}')",
		},
		{
			name:       "double quoted placeholder",
			expression: `contains(body, "{{server_token}}")`,
		},
	}

	for _, expression := range expressions {
		t.Run(expression.name, func(t *testing.T) {
			for _, item := range items {
				t.Run(item.name, func(t *testing.T) {
					matcher := mustCompileDSLMatcher(t, expression.expression)

					require.True(t, matcher.MatchDSL(map[string]interface{}{
						"template-id":  "test-template",
						"body":         "prefix " + item.value + " suffix",
						"server_token": item.value,
					}))
				})
			}
		})
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

func TestMatchWords_CaseInsensitive_DynamicValue(t *testing.T) {
	m := &Matcher{
		Type:            MatcherTypeHolder{MatcherType: WordsMatcher},
		CaseInsensitive: true,
		Words:           []string{"{{host}}"},
	}
	require.NoError(t, m.CompileMatchers())

	isMatched, matched := m.MatchWords("visit example.com now", map[string]interface{}{"host": "Example.COM"})
	require.True(t, isMatched, "Could not match case-insensitive dynamic word against lowercased corpus")
	require.Equal(t, []string{"example.com"}, matched)
}

func TestMatchOffset(t *testing.T) {
	offset0 := 0
	offset2 := 2

	t.Run("word at start", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: WordsMatcher}, Words: []string{"MZ"}, Offset: &offset0}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchWords("MZ....", nil)
		require.True(t, ok)
		require.Equal(t, []string{"MZ"}, snippets)
		ok, _ = m.MatchWords("xMZ...", nil)
		require.False(t, ok)
	})

	t.Run("word at mid offset", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: WordsMatcher}, Words: []string{"AB"}, Offset: &offset2}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchWords("xxAByy", nil)
		require.True(t, ok)
		ok, _ = m.MatchWords("ABxxxx", nil)
		require.False(t, ok)
		ok, _ = m.MatchWords("xx--AB", nil)
		require.False(t, ok)
	})

	t.Run("binary at start", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: BinaryMatcher}, Binary: []string{"4d5a"}, Offset: &offset0}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchBinary("MZ....")
		require.True(t, ok)
		ok, _ = m.MatchBinary("xMZ...")
		require.False(t, ok)
	})

	t.Run("binary at mid offset", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: BinaryMatcher}, Binary: []string{"4d5a"}, Offset: &offset2}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchBinary("xxMZ....")
		require.True(t, ok)
		ok, _ = m.MatchBinary("xx--MZ")
		require.False(t, ok)
	})

	t.Run("regex must start at offset", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Regex: []string{"MZ"}, Offset: &offset0}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchRegex("MZPE")
		require.True(t, ok)
		require.Equal(t, []string{"MZ"}, snippets)
		ok, _ = m.MatchRegex("xxMZ")
		require.False(t, ok)
	})

	t.Run("regex preserves assertion context", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Regex: []string{"^MZ"}, Offset: &offset2}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchRegex("xxMZ")
		require.False(t, ok)
	})

	t.Run("negative offset rejected", func(t *testing.T) {
		neg := -1
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: WordsMatcher}, Words: []string{"MZ"}, Offset: &neg}
		require.Error(t, m.CompileMatchers())
	})
}

func newOffsetRegexMatcher(t *testing.T, offset int, regexes ...string) *Matcher {
	t.Helper()

	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Regex: regexes, Offset: &offset}
	require.NoError(t, m.CompileMatchers())
	return m
}

func TestMatchRegexOffset(t *testing.T) {
	tests := []struct {
		name    string
		regex   string
		corpus  string
		offset  int
		matched bool
		snippet string
	}{
		{name: "overlapping alternative at offset", regex: "ab|b", corpus: "ab", offset: 1, matched: true, snippet: "b"},
		{name: "leftmost alternative at offset", regex: "ab|b", corpus: "ab", offset: 0, matched: true, snippet: "ab"},
		{name: "match before offset is ignored", regex: "ab", corpus: "abab", offset: 1, matched: false},
		{name: "match after offset is ignored", regex: "b", corpus: "ab", offset: 0, matched: false},
		{name: "greedy match keeps full span", regex: "a+", corpus: "baaa", offset: 1, matched: true, snippet: "aaa"},
		{name: "start of text anchor at offset zero", regex: "^MZ", corpus: "MZxx", offset: 0, matched: true, snippet: "MZ"},
		{name: "start of text anchor mid corpus", regex: "^MZ", corpus: "xxMZ", offset: 2, matched: false},
		{name: "absolute start anchor mid corpus", regex: `\AMZ`, corpus: "xxMZ", offset: 2, matched: false},
		{name: "multiline anchor after newline", regex: "(?m)^MZ", corpus: "xx\nMZ", offset: 3, matched: true, snippet: "MZ"},
		{name: "multiline anchor without newline", regex: "(?m)^MZ", corpus: "xxMZ", offset: 2, matched: false},
		{name: "word boundary after word character", regex: `\bfoo`, corpus: "xfoo", offset: 1, matched: false},
		{name: "word boundary after separator", regex: `\bfoo`, corpus: " foo", offset: 1, matched: true, snippet: "foo"},
		{name: "non word boundary inside word", regex: `\Bar`, corpus: "bar", offset: 1, matched: true, snippet: "ar"},
		{name: "non word boundary after separator", regex: `\Bar`, corpus: "-ar", offset: 1, matched: false},
		{name: "end of text anchor honored", regex: "b$", corpus: "ab", offset: 1, matched: true, snippet: "b"},
		{name: "end of text anchor rejected", regex: "b$", corpus: "abc", offset: 1, matched: false},
		{name: "case insensitive flag preserved", regex: "(?i)mz", corpus: "xxMZ", offset: 2, matched: true, snippet: "MZ"},
		{name: "offset inside multi byte rune", regex: "MZ", corpus: "éMZ", offset: 1, matched: false},
		{name: "offset after multi byte rune", regex: "MZ", corpus: "éMZ", offset: 2, matched: true, snippet: "MZ"},
		{name: "offset past corpus", regex: "MZ", corpus: "MZ", offset: 5, matched: false},
		{name: "zero width match at corpus end", regex: "x*", corpus: "ab", offset: 2, matched: true, snippet: ""},
		{name: "invalid utf8 byte as context", regex: "MZ", corpus: "\xffMZ", offset: 1, matched: true, snippet: "MZ"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newOffsetRegexMatcher(t, test.offset, test.regex)
			ok, snippets := m.MatchRegex(test.corpus)
			require.Equal(t, test.matched, ok)
			if test.matched {
				require.Equal(t, []string{test.snippet}, snippets)
			}
		})
	}

	t.Run("multiple regexes keep their anchored variant", func(t *testing.T) {
		offset := 1
		m := &Matcher{
			Type:      MatcherTypeHolder{MatcherType: RegexMatcher},
			Regex:     []string{"b", "bc"},
			Condition: "and",
			Offset:    &offset,
		}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchRegex("abc")
		require.True(t, ok)
		require.Equal(t, []string{"b", "bc"}, snippets)

		ok, _ = m.MatchRegex("xbc")
		require.True(t, ok)
		ok, _ = m.MatchRegex("bcx")
		require.False(t, ok)
	})

	t.Run("anchored variant compiled on demand", func(t *testing.T) {
		m := newOffsetRegexMatcher(t, 1, "ab|b")
		m.offsetRegexCompiled = nil
		ok, snippets := m.MatchRegex("ab")
		require.True(t, ok)
		require.Equal(t, []string{"b"}, snippets)
	})

	t.Run("allocations do not grow with corpus size", func(t *testing.T) {
		m := newOffsetRegexMatcher(t, 4, "a{3}")
		small := strings.Repeat("a", 1<<10)
		large := strings.Repeat("a", 1<<20)

		smallAllocs := testing.AllocsPerRun(20, func() { _, _ = m.MatchRegex(small) })
		largeAllocs := testing.AllocsPerRun(20, func() { _, _ = m.MatchRegex(large) })
		require.LessOrEqual(t, largeAllocs, smallAllocs+1, "offset matching should not allocate per corpus match")
		require.LessOrEqual(t, largeAllocs, float64(8), "offset matching should allocate a constant amount")
	})
}

func BenchmarkMatchRegexOffset(b *testing.B) {
	dense := strings.Repeat("ab", 1<<19)

	benchmarks := []struct {
		name   string
		regex  string
		corpus string
		offset int
	}{
		{name: "match at start of dense corpus", regex: "ab", corpus: dense, offset: 0},
		{name: "overlapping alternative", regex: "ab|b", corpus: dense, offset: 1},
		{name: "match near end of dense corpus", regex: "ab", corpus: dense, offset: len(dense) - 2},
		{name: "no match in dense corpus", regex: "zz", corpus: dense, offset: 3},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			offset := bm.offset
			m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Regex: []string{bm.regex}, Offset: &offset}
			if err := m.CompileMatchers(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = m.MatchRegex(bm.corpus)
			}
		})
	}
}

func TestMatcher_MatchDSL_ErrorHandling(t *testing.T) {
	// First expression errors (division by zero), second is true
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: DSLMatcher}, Condition: "or", DSL: []string{"1 / 0", "1 == 1"}}
	require.NoError(t, m.CompileMatchers())
	ok := m.MatchDSL(map[string]interface{}{})
	require.True(t, ok)
}
