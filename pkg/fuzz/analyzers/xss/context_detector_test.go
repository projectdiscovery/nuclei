package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectReflections_HTMLText(t *testing.T) {
	body := `<html><body><p>Hello MARKER123 world</p></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextHTMLText, refs[0].Context)
}

func TestDetectReflections_AttributeDoubleQuoted(t *testing.T) {
	body := `<html><body><input type="text" value="MARKER123"></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextAttribute, refs[0].Context)
	require.Equal(t, "value", refs[0].AttributeName)
}

func TestDetectReflections_AttributeSingleQuoted(t *testing.T) {
	body := `<html><body><input type='text' value='MARKER123'></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextAttribute, refs[0].Context)
}

func TestDetectReflections_AttributeUnquoted(t *testing.T) {
	body := `<html><body><input type=text value=MARKER123></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	// The HTML tokenizer may normalize unquoted attrs to double-quoted,
	// so we accept either classification.
	require.Contains(t,
		[]ContextType{ContextAttribute, ContextAttributeUnquoted},
		refs[0].Context,
	)
}

func TestDetectReflections_ScriptBlock(t *testing.T) {
	body := `<html><head><script>var x = MARKER123;</script></head></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextScript, refs[0].Context)
}

func TestDetectReflections_ScriptString(t *testing.T) {
	body := `<html><head><script>var x = "Hello MARKER123";</script></head></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextScriptString, refs[0].Context)
}

func TestDetectReflections_ScriptSingleQuoteString(t *testing.T) {
	body := `<html><head><script>var x = 'Hello MARKER123';</script></head></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextScriptString, refs[0].Context)
}

func TestDetectReflections_Comment(t *testing.T) {
	body := `<html><!-- user: MARKER123 --><body></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextHTMLComment, refs[0].Context)
}

func TestDetectReflections_Style(t *testing.T) {
	body := `<html><head><style>body { color: MARKER123; }</style></head></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextStyle, refs[0].Context)
}

func TestDetectReflections_EventHandler(t *testing.T) {
	body := `<html><body><div onclick="MARKER123">click</div></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextScript, refs[0].Context)
	require.Equal(t, "onclick", refs[0].AttributeName)
}

func TestDetectReflections_MultipleReflections(t *testing.T) {
	body := `<html><body><p>MARKER123</p><input value="MARKER123"><script>x="MARKER123"</script></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.GreaterOrEqual(t, len(refs), 2)

	// Verify we detected at least HTML text and attribute contexts.
	contexts := make(map[ContextType]bool)
	for _, r := range refs {
		contexts[r.Context] = true
	}
	require.True(t, contexts[ContextHTMLText], "expected HTML text context")
	require.True(t, contexts[ContextAttribute], "expected attribute context")
}

func TestDetectReflections_NoMarker(t *testing.T) {
	body := `<html><body>Hello world</body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Nil(t, refs)
}

func TestDetectReflections_Title(t *testing.T) {
	body := `<html><head><title>MARKER123</title></head><body></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	// title is RCDATA context, we classify it as HTMLText since the
	// breakout strategy is the same (close the tag and inject).
	require.Equal(t, ContextHTMLText, refs[0].Context)
}

func TestDetectReflections_Textarea(t *testing.T) {
	body := `<html><body><textarea>MARKER123</textarea></body></html>`
	refs := DetectReflections(body, "MARKER123")
	require.Len(t, refs, 1)
	require.Equal(t, ContextHTMLText, refs[0].Context)
}

func TestDetectReflections_AttributeKeyInjection(t *testing.T) {
	// Marker in attribute name indicates attribute-name injection.
	// We use a lowercase marker because the HTML tokenizer lowercases
	// attribute names, so an uppercase marker in a key will be
	// normalized and the byte comparison would fail.
	body := `<html><body><div marker123="test">text</div></body></html>`
	refs := DetectReflections(body, "marker123")
	require.NotEmpty(t, refs)
	hasAttrContext := false
	for _, r := range refs {
		if r.Context == ContextAttribute {
			hasAttrContext = true
		}
	}
	require.True(t, hasAttrContext)
}

func TestIsEventHandler(t *testing.T) {
	tests := []struct {
		attr   string
		expect bool
	}{
		{"onclick", true},
		{"onerror", true},
		{"onload", true},
		{"ONCLICK", true},
		{"OnMouseOver", true},
		{"class", false},
		{"href", false},
		{"on", false},       // too short to be a real handler
		{"ongoing", false},  // starts with "on" but not a handler
		{"onx", false},      // not a real handler
		{"ontouchstart", true},
		{"onfullscreenchange", true},
	}
	for _, tc := range tests {
		t.Run(tc.attr, func(t *testing.T) {
			result := isEventHandler([]byte(tc.attr))
			require.Equal(t, tc.expect, result, "isEventHandler(%q)", tc.attr)
		})
	}
}

func TestClassifyScriptContext_BareCode(t *testing.T) {
	raw := `var x = MARKER123;`
	ctx := classifyScriptContext(raw, "MARKER123")
	require.Equal(t, ContextScript, ctx)
}

func TestClassifyScriptContext_DoubleQuotedString(t *testing.T) {
	raw := `var x = "Hello MARKER123";`
	ctx := classifyScriptContext(raw, "MARKER123")
	require.Equal(t, ContextScriptString, ctx)
}

func TestClassifyScriptContext_SingleQuotedString(t *testing.T) {
	raw := `var x = 'Hello MARKER123';`
	ctx := classifyScriptContext(raw, "MARKER123")
	require.Equal(t, ContextScriptString, ctx)
}

func TestClassifyScriptContext_BacktickTemplate(t *testing.T) {
	raw := "var x = `Hello MARKER123`;"
	ctx := classifyScriptContext(raw, "MARKER123")
	require.Equal(t, ContextScriptString, ctx)
}

func TestClassifyScriptContext_EscapedQuote(t *testing.T) {
	// The backslash escapes the first quote, so we are still inside
	// the string when the marker appears.
	raw := `var x = "He said \"Hello MARKER123\"";`
	ctx := classifyScriptContext(raw, "MARKER123")
	require.Equal(t, ContextScriptString, ctx)
}

func TestDetectAvailableChars_AllPresent(t *testing.T) {
	marker := `nxssabc123<>"'/`
	body := `<html><body>` + marker + `</body></html>`
	chars := DetectAvailableChars(body, marker)
	require.True(t, chars.AngleBrackets)
	require.True(t, chars.DoubleQuote)
	require.True(t, chars.SingleQuote)
	require.True(t, chars.ForwardSlash)
}

func TestDetectAvailableChars_SomeEncoded(t *testing.T) {
	// Simulate the server encoding angle brackets but leaving quotes
	marker := `nxssabc123<>"'/`
	encoded := `nxssabc123&lt;&gt;"'/` // < and > were encoded
	body := `<html><body>` + encoded + `</body></html>`
	chars := DetectAvailableChars(body, marker)
	// The full marker is NOT present in the body, so angle brackets
	// should be detected as unavailable.
	require.False(t, chars.AngleBrackets)
}
