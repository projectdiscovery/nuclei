package xss

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testMarker = "NUCLEI_XSS_MARKER"

// --- Empty / edge-case inputs ---

func TestDetectReflections_EmptyInputs(t *testing.T) {
	require.Nil(t, DetectReflections("", testMarker))
	require.Nil(t, DetectReflections("hello", ""))
	require.Nil(t, DetectReflections("hello world", testMarker))
}

// --- HTML text contexts ---

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

// --- Attribute contexts ---

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

func TestDetectReflections_SelfClosingTag(t *testing.T) {
	body := `<img src="` + testMarker + `" />`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextURLAttribute, got[0].Context)
}

// --- Event handler contexts ---

func TestDetectReflections_EventHandlerOnclick(t *testing.T) {
	body := `<div onclick="` + testMarker + `">click</div>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextEventHandler, got[0].Context)
	require.Equal(t, "onclick", got[0].AttributeName)
}

func TestDetectReflections_EventHandlerOnError(t *testing.T) {
	body := `<img onerror="` + testMarker + `" src=x>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextEventHandler, got[0].Context)
}

func TestDetectReflections_EventHandlerOnMouseOver(t *testing.T) {
	body := `<span onmouseover="` + testMarker + `">hover</span>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextEventHandler, got[0].Context)
}

func TestDetectReflections_EventHandlerOnFocus(t *testing.T) {
	body := `<input onfocus="` + testMarker + `">`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextEventHandler, got[0].Context)
}

func TestDetectReflections_EventHandlerMixedCase(t *testing.T) {
	body := `<div OnClick="` + testMarker + `">click</div>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextEventHandler, got[0].Context)
}

func TestDetectReflections_NonEventOnAttribute(t *testing.T) {
	// "data-onclick" should NOT be treated as an event handler
	body := `<div data-onclick="` + testMarker + `">click</div>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.NotEqual(t, ContextEventHandler, got[0].Context)
}

// --- Script contexts ---

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

func TestDetectReflections_ScriptInsideSVG(t *testing.T) {
	body := `<svg><script>var x = "` + testMarker + `";</script></svg>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	// SVG script blocks should still be detected
	found := false
	for _, r := range got {
		if r.Context == ContextScriptStringDouble || r.Context == ContextScriptBlock {
			found = true
		}
	}
	require.True(t, found, "should detect script context inside SVG")
}

func TestDetectReflections_MultipleScriptsMarkerInSecond(t *testing.T) {
	body := `<script>var a = 1;</script><script>var b = "` + testMarker + `";</script>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextScriptStringDouble, got[0].Context)
}

// --- Comment ---

func TestDetectReflections_Comment(t *testing.T) {
	body := `<html><!-- user: ` + testMarker + ` --></html>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextComment, got[0].Context)
}

func TestDetectReflections_MultiLineComment(t *testing.T) {
	body := `<!--
	some comment
	` + testMarker + `
	more comment
	-->`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextComment, got[0].Context)
}

// --- RCDATA / Special elements ---

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

// --- Multiple reflections / priority ---

func TestDetectReflections_MultipleReflections(t *testing.T) {
	body := `<div>` + testMarker + `</div><input value="` + testMarker + `">`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 2)
}

func TestDetectReflections_PriorityOrder(t *testing.T) {
	body := `<div>` + testMarker + `</div><script>var x="` + testMarker + `";</script>`
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 2)
	found := false
	for _, r := range got {
		if r.Context == ContextScriptStringDouble {
			found = true
		}
	}
	require.True(t, found)
}

func TestDetectReflections_ScriptWinsOverAll(t *testing.T) {
	body := `<!-- ` + testMarker + ` --><div>` + testMarker + `</div><input value="` + testMarker + `"><script>` + testMarker + `</script>`
	got := DetectReflections(body, testMarker)
	require.True(t, len(got) >= 4)
	// Script context should have highest priority (lowest weight)
	for _, r := range got {
		if r.Context == ContextScriptBlock {
			require.LessOrEqual(t, r.PriorityWeight, 40) // must beat HTMLText
		}
	}
}

// --- Case insensitivity ---

func TestDetectReflections_CaseInsensitiveTags(t *testing.T) {
	body := `<SCRIPT>var x = "` + testMarker + `";</SCRIPT>`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
	ctx := got[0].Context
	require.True(t, ctx == ContextScriptStringDouble || ctx == ContextScriptBlock,
		"expected script context, got %s", ctx)
}

// --- Malformed HTML (drain logic) ---

func TestDetectReflections_MalformedUnclosedTag(t *testing.T) {
	body := `<html><body><div>` + testMarker + `<span>unclosed`
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got)
}

func TestDetectReflections_TruncatedDocument(t *testing.T) {
	body := `<html><body><p>Hello</p><div>` + testMarker
	got := DetectReflections(body, testMarker)
	require.NotEmpty(t, got, "drain logic should catch reflection in truncated HTML")
}

func TestDetectReflections_DrainCountsCorrectly(t *testing.T) {
	// Two marker occurrences but one is in truncated/unfound context
	body := `<div>` + testMarker + `</div>` + testMarker
	got := DetectReflections(body, testMarker)
	require.Len(t, got, 2, "drain should fill in the missing reflection")
}

// --- Large page ---

func TestDetectReflections_LargePage(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < 500; i++ {
		sb.WriteString(fmt.Sprintf(`<div class="item-%d"><p>Lorem ipsum dolor sit amet.</p></div>`, i))
	}
	sb.WriteString(`<input type="text" value="` + testMarker + `">`)
	sb.WriteString("</body></html>")
	got := DetectReflections(sb.String(), testMarker)
	require.NotEmpty(t, got)
	require.Equal(t, ContextAttributeDoubleQuoted, got[0].Context)
}

// --- CharacterSet detection tests ---

func TestDetectAvailableChars_AllPresent(t *testing.T) {
	original := `probe<>"'/` + "`(="
	reflected := `probe<>"'/` + "`(="
	chars := DetectAvailableChars(reflected, original)
	require.True(t, chars.LessThan)
	require.True(t, chars.GreaterThan)
	require.True(t, chars.DoubleQuote)
	require.True(t, chars.SingleQuote)
	require.True(t, chars.Slash)
	require.True(t, chars.Backtick)
	require.True(t, chars.Parenthesis)
	require.True(t, chars.Equals)
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
	original := "simpleprobe"
	reflected := "simpleprobe"
	chars := DetectAvailableChars(reflected, original)
	require.True(t, chars.LessThan)
	require.True(t, chars.GreaterThan)
}

func TestDetectAvailableChars_ParenthesisEncoded(t *testing.T) {
	original := `probe()`
	reflected := `probe&#40;&#41;`
	chars := DetectAvailableChars(reflected, original)
	require.False(t, chars.Parenthesis)
}

// --- Double encoding / Unicode escape tests ---

func TestDetectDoubleEncoding(t *testing.T) {
	require.True(t, DetectDoubleEncoding("hello &amp;lt; world"))
	require.True(t, DetectDoubleEncoding("test &amp;gt; value"))
	require.True(t, DetectDoubleEncoding("&amp;quot; stuff"))
	require.False(t, DetectDoubleEncoding("&lt;script&gt;"))
	require.False(t, DetectDoubleEncoding("normal text"))
}

func TestDetectUnicodeEscape(t *testing.T) {
	require.True(t, DetectUnicodeEscape(`value: \u003cscript\u003e`))
	require.True(t, DetectUnicodeEscape(`\u0022hello\u0022`))
	require.False(t, DetectUnicodeEscape(`<script>alert(1)</script>`))
	require.False(t, DetectUnicodeEscape("normal text"))
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
		ContextEventHandler:          "event_handler",
		ContextStyle:                 "style",
		ContextScriptTemplate:        "script_template",
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
	require.True(t, isURLAttribute("srcset"))
	require.True(t, isURLAttribute("ping"))
	require.False(t, isURLAttribute("class"))
	require.False(t, isURLAttribute("id"))
	require.False(t, isURLAttribute("value"))
}

// --- isEventHandler tests ---

func TestIsEventHandler(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"onclick", true},
		{"ONCLICK", true},
		{"OnClick", true},
		{"onmouseover", true},
		{"onerror", true},
		{"onload", true},
		{"onfocus", true},
		{"onanimationiteration", true},
		{"onfocusin", true},
		{"onpointerdown", true},
		{"ontoggle", true},
		{"onwheel", true},
		{"class", false},
		{"href", false},
		{"src", false},
		{"data-onclick", false},
		{"onnonexistent", false},
		{"on", false},
		{"o", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, isEventHandler(tt.name), "isEventHandler(%q)", tt.name)
		})
	}
}
