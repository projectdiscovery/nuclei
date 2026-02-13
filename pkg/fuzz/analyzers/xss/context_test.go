package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyReflections_HTMLBody(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body><div>Hello ` + canary + ` World</div></body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextHTMLBody, reflections[0].Context)
}

func TestClassifyReflections_AttrDoubleQuoted(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body><input type="text" value="` + canary + `"></body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextHTMLAttrDoubleQuoted, reflections[0].Context)
}

func TestClassifyReflections_AttrSingleQuoted(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body><input type='text' value='` + canary + `'></body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextHTMLAttrSingleQuoted, reflections[0].Context)
}

func TestClassifyReflections_ScriptBlock(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><head><script>var data = ` + canary + `;</script></head></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextScriptBlock, reflections[0].Context)
}

func TestClassifyReflections_ScriptStringDouble(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><head><script>var x = "` + canary + `";</script></head></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextScriptStringDouble, reflections[0].Context)
}

func TestClassifyReflections_ScriptStringSingle(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><head><script>var x = '` + canary + `';</script></head></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextScriptStringSingle, reflections[0].Context)
}

func TestClassifyReflections_ScriptTemplateLiteral(t *testing.T) {
	canary := buildCanary(nil)
	body := "<html><head><script>var x = `" + canary + "`;</script></head></html>"

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextScriptTemplate, reflections[0].Context)
}

func TestClassifyReflections_HTMLComment(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body><!-- Comment: ` + canary + ` --></body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextHTMLComment, reflections[0].Context)
}

func TestClassifyReflections_StyleBlock(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><head><style>.cls { color: ` + canary + `; }</style></head></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextStyleBlock, reflections[0].Context)
}

func TestClassifyReflections_URLAttribute(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body><a href="` + canary + `">Link</a></body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextURLAttribute, reflections[0].Context)
}

func TestClassifyReflections_MultipleReflections(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body>` +
		`<div>` + canary + `</div>` +
		`<input value="` + canary + `">` +
		`<script>var x = '` + canary + `';</script>` +
		`</body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Len(t, reflections, 3)

	contexts := make(map[ReflectionContext]bool)
	for _, r := range reflections {
		contexts[r.Context] = true
	}
	require.True(t, contexts[ContextHTMLBody])
	require.True(t, contexts[ContextHTMLAttrDoubleQuoted])
	require.True(t, contexts[ContextScriptStringSingle])
}

func TestClassifyReflections_NoReflection(t *testing.T) {
	canary := buildCanary(nil)
	body := `<html><body><div>No canary here</div></body></html>`

	reflections := ClassifyReflections(body, canary)
	require.Nil(t, reflections)
}

func TestClassifyReflections_EmptyInputs(t *testing.T) {
	require.Nil(t, ClassifyReflections("", "canary"))
	require.Nil(t, ClassifyReflections("body", ""))
	require.Nil(t, ClassifyReflections("", ""))
}

func TestClassifyReflections_CaseInsensitive(t *testing.T) {
	canary := buildCanary(nil)
	upper := `<HTML><BODY><DIV>` + canary + `</DIV></BODY></HTML>`

	reflections := ClassifyReflections(upper, canary)
	require.Len(t, reflections, 1)
	require.Equal(t, ContextHTMLBody, reflections[0].Context)
}

func TestIsExploitable_HTMLBody(t *testing.T) {
	canary := buildCanary(nil) // includes < > ' " `
	body := `<div>` + canary + `</div>`

	ref := Reflection{Context: ContextHTMLBody, Position: 5}
	require.True(t, isExploitable(body, canary, ref))
}

func TestIsExploitable_HTMLBodyEncoded(t *testing.T) {
	// If < and > are encoded, it's not exploitable in HTML body
	encoded := "xc4n4ry&lt;&gt;'\"` xc4n4ry"
	body := `<div>` + encoded + `</div>`

	ref := Reflection{Context: ContextHTMLBody, Position: 5}
	require.False(t, isExploitable(body, encoded, ref))
}

func TestIsExploitable_AttrDoubleQuoted(t *testing.T) {
	canary := buildCanary(nil)
	body := `<input value="` + canary + `">`

	ref := Reflection{Context: ContextHTMLAttrDoubleQuoted, Position: 14}
	require.True(t, isExploitable(body, canary, ref))
}

func TestIsExploitable_ScriptBlock(t *testing.T) {
	canary := buildCanary(nil)
	body := `<script>var x = ` + canary + `;</script>`

	ref := Reflection{Context: ContextScriptBlock, Position: 16}
	// Script block is always exploitable if reflected
	require.True(t, isExploitable(body, canary, ref))
}

func TestBuildCanary(t *testing.T) {
	canary := buildCanary(nil)
	require.Contains(t, canary, canaryPrefix)
	require.Contains(t, canary, "<")
	require.Contains(t, canary, ">")
	require.Contains(t, canary, "'")
	require.Contains(t, canary, "\"")
	require.Contains(t, canary, "`")
}

func TestBuildCanary_CustomPrefix(t *testing.T) {
	params := map[string]interface{}{
		"canary_prefix": "mycanary",
	}
	canary := buildCanary(params)
	require.Contains(t, canary, "mycanary")
	require.NotContains(t, canary, canaryPrefix)
}

func TestContextString(t *testing.T) {
	tests := []struct {
		ctx      ReflectionContext
		expected string
	}{
		{ContextHTMLBody, "html-body"},
		{ContextHTMLAttrDoubleQuoted, "html-attr-double-quoted"},
		{ContextHTMLAttrSingleQuoted, "html-attr-single-quoted"},
		{ContextHTMLAttrUnquoted, "html-attr-unquoted"},
		{ContextScriptBlock, "script-block"},
		{ContextScriptStringDouble, "script-string-double"},
		{ContextScriptStringSingle, "script-string-single"},
		{ContextScriptTemplate, "script-template"},
		{ContextHTMLComment, "html-comment"},
		{ContextStyleBlock, "style-block"},
		{ContextURLAttribute, "url-attribute"},
		{ContextNone, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.ctx.String())
		})
	}
}

func TestClassifyJSContext(t *testing.T) {
	tests := []struct {
		name     string
		segment  string
		expected ReflectionContext
	}{
		{"raw block", "var x = ", ContextScriptBlock},
		{"double string", `var x = "hello `, ContextScriptStringDouble},
		{"single string", `var x = 'hello `, ContextScriptStringSingle},
		{"template literal", "var x = `hello ", ContextScriptTemplate},
		{"escaped double", `var x = "hello \" still in `, ContextScriptStringDouble},
		{"closed double", `var x = "hello"; var y = `, ContextScriptBlock},
		{"nested quotes", `var x = "it's fine"; var y = `, ContextScriptBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyJSContext(tt.segment)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatFindings(t *testing.T) {
	reflections := []Reflection{
		{Context: ContextHTMLBody, Position: 10},
		{Context: ContextScriptBlock, Position: 200},
	}
	details := formatFindings(reflections)
	require.Contains(t, details, "2 context(s)")
	require.Contains(t, details, "html-body")
	require.Contains(t, details, "script-block")
}
