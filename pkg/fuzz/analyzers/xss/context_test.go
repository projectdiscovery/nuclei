package xss

import (
	"strings"
	"testing"
)

func TestClassifyReflections_HTMLBody(t *testing.T) {
	canary := "xss1234<>'\"`"
	body := `<html><body><div>` + canary + `</div></body></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextHTMLBody {
		t.Fatalf("expected html-body context, got %s", findings[0].Context)
	}
	if !findings[0].Exploitable {
		t.Fatal("expected exploitable (< and > present)")
	}
}

func TestClassifyReflections_AttrDoubleQuoted(t *testing.T) {
	canary := "xss5678<>'\"`"
	body := `<html><input type="text" value="` + canary + `"></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextHTMLAttrDoubleQuoted {
		t.Fatalf("expected html-attr-double-quoted, got %s", findings[0].Context)
	}
	if !findings[0].Exploitable {
		t.Fatal("expected exploitable (double quote present)")
	}
}

func TestClassifyReflections_AttrSingleQuoted(t *testing.T) {
	canary := "xss9012<>'\"`"
	body := `<html><input type='text' value='` + canary + `'></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextHTMLAttrSingleQuoted {
		t.Fatalf("expected html-attr-single-quoted, got %s", findings[0].Context)
	}
	if !findings[0].Exploitable {
		t.Fatal("expected exploitable (single quote present)")
	}
}

func TestClassifyReflections_AttrUnquoted(t *testing.T) {
	canary := "xss3456<>'\"`"
	body := `<html><input type=text value=` + canary + `></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextHTMLAttrUnquoted {
		t.Fatalf("expected html-attr-unquoted, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_ScriptBlock(t *testing.T) {
	canary := "xss7890<>'\"`"
	body := `<html><script>var x = ` + canary + `;</script></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextScriptBlock {
		t.Fatalf("expected script-block, got %s", findings[0].Context)
	}
	if !findings[0].Exploitable {
		t.Fatal("expected exploitable")
	}
}

func TestClassifyReflections_ScriptStringDouble(t *testing.T) {
	canary := "xss1111<>'\"`"
	body := `<html><script>var x = "` + canary + `</script></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextScriptStringDouble {
		t.Fatalf("expected script-string-double, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_ScriptStringSingle(t *testing.T) {
	canary := "xss2222<>'\"`"
	body := `<html><script>var x = '` + canary + `</script></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextScriptStringSingle {
		t.Fatalf("expected script-string-single, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_ScriptTemplateLiteral(t *testing.T) {
	canary := "xss3333<>'\"`"
	body := "<html><script>var x = `" + canary + "</script></html>"
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextScriptTemplateLiteral {
		t.Fatalf("expected script-template, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_HTMLComment(t *testing.T) {
	canary := "xss4444<>'\"`"
	body := `<html><!-- ` + canary + ` --></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextHTMLComment {
		t.Fatalf("expected html-comment, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_StyleBlock(t *testing.T) {
	canary := "xss5555<>'\"`"
	body := `<html><style>body { color: ` + canary + `; }</style></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextStyleBlock {
		t.Fatalf("expected style-block, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_URLAttribute(t *testing.T) {
	canary := "xss6666<>'\"`"
	body := `<html><a href="` + canary + `">link</a></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextURLAttribute {
		t.Fatalf("expected url-attribute, got %s", findings[0].Context)
	}
}

func TestClassifyReflections_MultipleReflections(t *testing.T) {
	canary := "xss7777<>'\"`"
	body := `<html><div>` + canary + `</div><script>var x = "` + canary + `";</script></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Context != ContextHTMLBody {
		t.Fatalf("expected first finding html-body, got %s", findings[0].Context)
	}
	if findings[1].Context != ContextScriptStringDouble {
		t.Fatalf("expected second finding script-string-double, got %s", findings[1].Context)
	}
}

func TestClassifyReflections_NoReflection(t *testing.T) {
	canary := "xss8888<>'\"`"
	body := `<html><body>nothing here</body></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestClassifyReflections_EmptyInputs(t *testing.T) {
	if findings := classifyReflections("", "canary"); findings != nil {
		t.Fatal("expected nil for empty body")
	}
	if findings := classifyReflections("body", ""); findings != nil {
		t.Fatal("expected nil for empty canary")
	}
}

func TestClassifyReflections_CaseInsensitive(t *testing.T) {
	canary := "XSS9999<>'\"`"
	body := `<html><body>` + "xss9999<>'\"`" + `</body></html>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (case-insensitive), got %d", len(findings))
	}
}

func TestIsExploitable_HTMLBody(t *testing.T) {
	canary := "xss1234<>'\"`"
	body := `<div>` + canary + `</div>`
	exploitable, breakout := isExploitable(ContextHTMLBody, body, 5, canary)
	if !exploitable {
		t.Fatal("expected exploitable for html-body with < and >")
	}
	if breakout != "<>" {
		t.Fatalf("expected breakout '<>', got '%s'", breakout)
	}
}

func TestIsExploitable_HTMLBodyEncoded(t *testing.T) {
	canary := "xss1234&lt;&gt;'\"`"
	body := `<div>` + canary + `</div>`
	exploitable, _ := isExploitable(ContextHTMLBody, body, 5, canary)
	if exploitable {
		t.Fatal("should not be exploitable when < > are encoded")
	}
}

func TestIsExploitable_AttrDoubleQuoted(t *testing.T) {
	canary := "xss5678<>'\"`"
	body := `<input value="` + canary + `">`
	exploitable, _ := isExploitable(ContextHTMLAttrDoubleQuoted, body, 14, canary)
	if !exploitable {
		t.Fatal("expected exploitable for double-quoted attr with double quote")
	}
}

func TestIsExploitable_ScriptBlock(t *testing.T) {
	canary := "xss7890<>'\"`"
	body := `<script>var x = ` + canary + `;</script>`
	exploitable, _ := isExploitable(ContextScriptBlock, body, 16, canary)
	if !exploitable {
		t.Fatal("expected exploitable for script block")
	}
}

func TestBuildCanary(t *testing.T) {
	canary := buildCanary("test")
	if !strings.HasPrefix(canary, "test") {
		t.Fatal("canary should start with prefix")
	}
	for _, ch := range []string{"<", ">", "'", "\"", "`"} {
		if !strings.Contains(canary, ch) {
			t.Fatalf("canary missing probe char: %s", ch)
		}
	}
}

func TestBuildCanary_CustomPrefix(t *testing.T) {
	canary := buildCanary("custom")
	if !strings.HasPrefix(canary, "custom") {
		t.Fatal("canary should start with custom prefix")
	}
}

func TestContextString(t *testing.T) {
	tests := map[Context]string{
		ContextHTMLBody:              "html-body",
		ContextScriptBlock:           "script-block",
		ContextHTMLComment:           "html-comment",
		ContextHTMLAttrDoubleQuoted:  "html-attr-double-quoted",
		ContextScriptTemplateLiteral: "script-template",
	}
	for ctx, expected := range tests {
		if ctx.String() != expected {
			t.Fatalf("context %d: expected %s, got %s", ctx, expected, ctx.String())
		}
	}
}

func TestClassifyJSContext(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		expected Context
	}{
		{"bare code", `<script>var x = VALUE;`, ContextScriptBlock},
		{"double string", `<script>var x = "VALUE`, ContextScriptStringDouble},
		{"single string", `<script>var x = 'VALUE`, ContextScriptStringSingle},
		{"template literal", "<script>var x = `VALUE", ContextScriptTemplateLiteral},
		{"escaped quote", `<script>var x = "hello \"VALUE`, ContextScriptStringDouble},
		{"closed string", `<script>var x = "hello";VALUE`, ContextScriptBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyScriptContext(tt.script)
			if result != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestFormatFindings(t *testing.T) {
	findings := []Reflection{
		{Context: ContextHTMLBody, Exploitable: true, BreakoutChar: "<>"},
		{Context: ContextScriptBlock, Exploitable: false},
	}
	result := formatFindings(findings)
	if !strings.Contains(result, "2 reflection(s)") {
		t.Fatal("should mention 2 reflections")
	}
	if !strings.Contains(result, "html-body") {
		t.Fatal("should mention html-body context")
	}
	if !strings.Contains(result, "script-block") {
		t.Fatal("should mention script-block context")
	}
	if !strings.Contains(result, "exploitable") {
		t.Fatal("should mention exploitability")
	}
}

func TestFormatFindings_Empty(t *testing.T) {
	result := formatFindings(nil)
	if result != "" {
		t.Fatal("expected empty string for no findings")
	}
}

func TestURLAttribute_OnlyExploitableWithColon(t *testing.T) {
	// Canary with colon should be exploitable
	canaryWithColon := "javascript:alert(1)"
	body := `<a href="` + canaryWithColon + `">link</a>`
	findings := classifyReflections(body, canaryWithColon)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context != ContextURLAttribute {
		t.Fatalf("expected url-attribute, got %s", findings[0].Context)
	}
	if !findings[0].Exploitable {
		t.Fatal("expected exploitable when colon present")
	}

	// Canary without colon should NOT be exploitable
	canaryNoColon := "xss1234noproto"
	body2 := `<a href="` + canaryNoColon + `">link</a>`
	findings2 := classifyReflections(body2, canaryNoColon)
	if len(findings2) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings2))
	}
	if findings2[0].Context != ContextURLAttribute {
		t.Fatalf("expected url-attribute, got %s", findings2[0].Context)
	}
	if findings2[0].Exploitable {
		t.Fatal("should not be exploitable without colon")
	}
}

func TestURLAttribute_NarrowDetection(t *testing.T) {
	// Reflection in a non-URL attribute of a tag that also has href
	// should NOT be classified as url-attribute
	canary := "xss4321test"
	body := `<a href="safe" class="` + canary + `">link</a>`
	findings := classifyReflections(body, canary)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Context == ContextURLAttribute {
		t.Fatal("should not be url-attribute when reflection is in class, not href")
	}
	if findings[0].Context != ContextHTMLAttrDoubleQuoted {
		t.Fatalf("expected html-attr-double-quoted, got %s", findings[0].Context)
	}
}

func TestIndexFold(t *testing.T) {
	tests := []struct {
		name     string
		haystack string
		needle   string
		expected int
	}{
		{"exact match", "hello world", "world", 6},
		{"case insensitive", "Hello WORLD", "world", 6},
		{"no match", "hello world", "xyz", -1},
		{"empty needle", "hello", "", 0},
		{"needle longer", "hi", "hello", -1},
		{"non-ascii", "Stra\u00dfe", "stra\u00dfe", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexFold(tt.haystack, tt.needle)
			if got != tt.expected {
				t.Fatalf("indexFold(%q, %q) = %d, want %d", tt.haystack, tt.needle, got, tt.expected)
			}
		})
	}
}
