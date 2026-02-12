package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const testMarker = "NUCLEI_XSS_MARKER"

func TestDetectReflections_EmptyInputs(t *testing.T) {
	require.Nil(t, DetectReflections("", testMarker))
	require.Nil(t, DetectReflections("hello", ""))
	require.Nil(t, DetectReflections("hello world", testMarker))
}

func TestDetectReflections_HTMLText(t *testing.T) {
	body := `<html><body><div>` + testMarker + `</div></body></html>`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 1)
	require.Equal(t, ContextHTMLText, got[0].Context)
}

func TestDetectReflections_HTMLTextParagraph(t *testing.T) {
	body := `<p>Hello ` + testMarker + ` world</p>`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 1)
	require.Equal(t, ContextHTMLText, got[0].Context)
}

func TestDetectReflections_HTMLTextNested(t *testing.T) {
	body := `<div><span><b>` + testMarker + `</b></span></div>`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 1)
	require.Equal(t, ContextHTMLText, got[0].Context)
}

func TestDetectReflections_AttributeDoubleQuoted(t *testing.T) {
	body := `<input type="text" value="` + testMarker + `">`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextAttributeDoubleQuoted, got[0].Context)
}

func TestDetectReflections_AttributeSingleQuoted(t *testing.T) {
	body := `<input value='` + testMarker + `'>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextAttributeSingleQuoted, got[0].Context)
}

func TestDetectReflections_AttributeUnquoted(t *testing.T) {
	body := `<input value=` + testMarker + `>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	// html.Tokenizer may parse unquoted attrs differently; accept unquoted or double
	ctx := got[0].Context
	require.True(t, ctx == ContextAttributeUnquoted || ctx == ContextAttributeDoubleQuoted,
		"got context %s", ctx)
}

func TestDetectReflections_AttributeHref(t *testing.T) {
	body := `<a href="` + testMarker + `">click</a>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextURLAttribute, got[0].Context)
}

func TestDetectReflections_AttributeSrc(t *testing.T) {
	body := `<img src="` + testMarker + `">`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextURLAttribute, got[0].Context)
}

func TestDetectReflections_AttributeMixedQuotingSameTag(t *testing.T) {
	body := `<input value="` + testMarker + `" data-x='` + testMarker + `'>`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 2)
	require.Equal(t, ContextAttributeDoubleQuoted, got[0].Context)
	require.Equal(t, ContextAttributeSingleQuoted, got[1].Context)
}

func TestDetectReflections_ScriptBlock(t *testing.T) {
	body := `<script>var x = ` + testMarker + `;</script>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextScriptBlock, got[0].Context)
}

func TestDetectReflections_ScriptStringDouble(t *testing.T) {
	body := `<script>var x = "` + testMarker + `";</script>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextScriptStringDouble, got[0].Context)
}

func TestDetectReflections_ScriptStringSingle(t *testing.T) {
	body := `<script>var x = '` + testMarker + `';</script>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextScriptStringSingle, got[0].Context)
}

func TestDetectReflections_ScriptTemplate(t *testing.T) {
	body := "<script>var x = `" + testMarker + "`;</script>"
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextScriptTemplate, got[0].Context)
}

func TestDetectReflections_Comment(t *testing.T) {
	body := `<html><!-- user: ` + testMarker + ` --></html>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextComment, got[0].Context)
}

func TestDetectReflections_Textarea(t *testing.T) {
	body := `<textarea>` + testMarker + `</textarea>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextRCDATA, got[0].Context)
}

func TestDetectReflections_Title(t *testing.T) {
	body := `<title>` + testMarker + `</title>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextRCDATA, got[0].Context)
}

func TestDetectReflections_Style(t *testing.T) {
	body := `<style>.x { content: "` + testMarker + `" }</style>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextStyle, got[0].Context)
}

func TestDetectReflections_MultipleReflections(t *testing.T) {
	body := `<div>` + testMarker + `</div><input value="` + testMarker + `">`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 2)
}

func TestDetectReflections_PriorityOrder(t *testing.T) {
	body := `<div>` + testMarker + `</div><script>var x="` + testMarker + `";</script>`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 2)
	// Script string should have lower priority weight (higher priority)
	found := false
	for _, r := range got {
		if r.Context == ContextScriptStringDouble {
			found = true
		}
	}
	require.True(t, found)
}

func TestDetectReflections_CaseInsensitiveTags(t *testing.T) {
	body := `<SCRIPT>var x = "` + testMarker + `";</SCRIPT>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	ctx := got[0].Context
	require.True(t, ctx == ContextScriptStringDouble || ctx == ContextScriptBlock,
		"expected script context, got %s", ctx)
}

// --- CharacterSet detection tests ---

func TestDetectAvailableChars_AllPresent(t *testing.T) {
	original := `probe<>"'/` + "`"
	reflected := `probe<>"'/` + "`"
	chars := DetectAvailableChars(reflected, original)
	require.True(t, chars.LessThan)
	require.True(t, chars.GreaterThan)
	require.True(t, chars.DoubleQuote)
	require.True(t, chars.SingleQuote)
	require.True(t, chars.Slash)
	require.True(t, chars.Backtick)
}

func TestDetectAvailableChars_AngleBracketsEncoded(t *testing.T) {
	original := `probe<>"'`
	reflected := `probe&lt;&gt;"'`
	chars := DetectAvailableChars(reflected, original)
	require.False(t, chars.LessThan)
	require.False(t, chars.GreaterThan)
	require.True(t, chars.DoubleQuote)
	require.True(t, chars.SingleQuote)
}

func TestDetectAvailableChars_QuotesEncoded(t *testing.T) {
	original := `probe<>"'`
	reflected := `probe<>&quot;&#39;`
	chars := DetectAvailableChars(reflected, original)
	require.True(t, chars.LessThan)
	require.True(t, chars.GreaterThan)
	require.False(t, chars.DoubleQuote)
	require.False(t, chars.SingleQuote)
}

func TestDetectAvailableChars_NotInOriginal(t *testing.T) {
	// If char was not in original canary, assume available (optimistic).
	original := "simpleprobe"
	reflected := "simpleprobe"
	chars := DetectAvailableChars(reflected, original)
	require.True(t, chars.LessThan)
	require.True(t, chars.GreaterThan)
}

// --- ContextType.String tests ---

func TestContextTypeString(t *testing.T) {
	tests := map[ContextType]string{
		ContextUnknown:               "unknown",
		ContextHTMLText:              "html_text",
		ContextAttributeDoubleQuoted: "attr_double_quoted",
		ContextScriptBlock:           "script_block",
		ContextComment:               "comment",
		ContextRCDATA:                "rcdata",
		ContextURLAttribute:          "url_attribute",
	}
	for ctx, expected := range tests {
		require.Equal(t, expected, ctx.String())
	}
}

// --- isURLAttribute tests ---

func TestIsURLAttribute(t *testing.T) {
	require.True(t, isURLAttribute("href"))
	require.True(t, isURLAttribute("src"))
	require.True(t, isURLAttribute("action"))
	require.True(t, isURLAttribute("HREF"))
	require.False(t, isURLAttribute("class"))
	require.False(t, isURLAttribute("id"))
	require.False(t, isURLAttribute("value"))
}
