package xss

import (
	"fmt"
	"strings"
	"testing"
)

const testMarker = "nucleiXSScanary"

// ==================== Core context detection ====================

func TestDetectReflections_HTMLText(t *testing.T) {
	body := `<html><body><p>Hello nucleiXSScanary world</p></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in HTML text")
	}
	if reflections[0].Context != ContextHTMLText {
		t.Fatalf("expected ContextHTMLText, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_AttributeDoubleQuoted(t *testing.T) {
	body := `<html><body><input value="nucleiXSScanary"></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in attribute")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextAttribute && r.AttrName == "value" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextAttribute for value attr, got %v", reflections)
	}
}

func TestDetectReflections_AttributeSingleQuoted(t *testing.T) {
	body := `<html><body><input value='nucleiXSScanary'></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in single-quoted attribute")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextAttribute && r.QuoteChar == '\'' {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected single-quoted ContextAttribute, got %v", reflections)
	}
}

func TestDetectReflections_ScriptBlock(t *testing.T) {
	body := `<html><body><script>var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in script")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("expected ContextScript, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptStringDouble(t *testing.T) {
	body := `<html><body><script>var x = "nucleiXSScanary";</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in script string")
	}
	if reflections[0].Context != ContextScriptString {
		t.Fatalf("expected ContextScriptString, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptStringSingle(t *testing.T) {
	body := `<html><body><script>var x = 'nucleiXSScanary';</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in script string")
	}
	if reflections[0].Context != ContextScriptString {
		t.Fatalf("expected ContextScriptString, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptStringBacktick(t *testing.T) {
	body := "<html><body><script>var x = `nucleiXSScanary`;</script></body></html>"
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in template literal")
	}
	if reflections[0].Context != ContextScriptString {
		t.Fatalf("expected ContextScriptString, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_HTMLComment(t *testing.T) {
	body := `<html><body><!-- nucleiXSScanary --></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in HTML comment")
	}
	if reflections[0].Context != ContextHTMLComment {
		t.Fatalf("expected ContextHTMLComment, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_StyleBlock(t *testing.T) {
	body := `<html><head><style>.x { background: url(nucleiXSScanary); }</style></head></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in style")
	}
	if reflections[0].Context != ContextStyle {
		t.Fatalf("expected ContextStyle, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_EventHandler(t *testing.T) {
	body := `<html><body><div onmouseover="nucleiXSScanary">test</div></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in event handler")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "onmouseover" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for event handler, got %v", reflections)
	}
}

func TestDetectReflections_NoReflection(t *testing.T) {
	body := `<html><body><p>Hello world</p></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) != 0 {
		t.Fatalf("expected no reflections, got %d", len(reflections))
	}
}

func TestDetectReflections_MultipleContexts(t *testing.T) {
	body := `<html><body>
		<p>nucleiXSScanary</p>
		<input value="nucleiXSScanary">
		<script>var x = "nucleiXSScanary";</script>
	</body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) < 3 {
		t.Fatalf("expected at least 3 reflections, got %d", len(reflections))
	}

	contexts := make(map[Context]bool)
	for _, r := range reflections {
		contexts[r.Context] = true
	}
	if !contexts[ContextHTMLText] {
		t.Error("expected ContextHTMLText in multiple reflections")
	}
	if !contexts[ContextAttribute] {
		t.Error("expected ContextAttribute in multiple reflections")
	}
	if !contexts[ContextScriptString] {
		t.Error("expected ContextScriptString in multiple reflections")
	}
}

func TestDetectReflections_Textarea(t *testing.T) {
	body := `<html><body><textarea>nucleiXSScanary</textarea></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in textarea (RCDATA element)")
	}
	if reflections[0].Context != ContextHTMLText {
		t.Fatalf("expected ContextHTMLText for RCDATA element, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_Title(t *testing.T) {
	body := `<html><head><title>nucleiXSScanary</title></head></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in title element")
	}
}

func TestDetectReflections_CaseInsensitive(t *testing.T) {
	body := `<html><body><p>NUCLEIxssCANARY</p></body></html>`
	reflections := DetectReflections(body, "nucleixsscanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive reflection detection")
	}
}

func TestDetectReflections_TagNameReflection(t *testing.T) {
	body := `<html><body><nucleiXSScanary>test</nucleiXSScanary></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in tag name")
	}
}

// ==================== Bug #7086 Fix 1: javascript: URI ====================

func TestDetectReflections_JavascriptURI(t *testing.T) {
	body := `<html><body><a href="javascript:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContextAttr(t, reflections, ContextScript, "href", "javascript: URI in href")
}

func TestDetectReflections_JavascriptURISingleQuoted(t *testing.T) {
	body := `<html><body><a href='javascript:nucleiXSScanary'>click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContextAttr(t, reflections, ContextScript, "href", "single-quoted javascript: URI")
}

func TestDetectReflections_JavascriptURIMixedCase(t *testing.T) {
	body := `<html><body><a href="JavaScript:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContextAttr(t, reflections, ContextScript, "href", "mixed-case JavaScript: URI")
}

func TestDetectReflections_JavascriptURILeadingWhitespace(t *testing.T) {
	body := `<html><body><a href="  javascript:alert(nucleiXSScanary)">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "javascript: URI with leading spaces")
}

func TestDetectReflections_JavascriptURILeadingTab(t *testing.T) {
	body := "<html><body><a href=\"\tjavascript:alert(nucleiXSScanary)\">click</a></body></html>"
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "javascript: URI with leading tab")
}

func TestDetectReflections_JavascriptURIInFormaction(t *testing.T) {
	body := `<html><body><button formaction="javascript:nucleiXSScanary">go</button></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContextAttr(t, reflections, ContextScript, "formaction", "javascript: URI in formaction")
}

func TestDetectReflections_NonJavascriptHref(t *testing.T) {
	body := `<html><body><a href="https://example.com/nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextAttribute, "normal https: href should stay ContextAttribute")
}

// ==================== Bug #7086 Fix 2: Non-executable script blocks ====================

func TestDetectReflections_JSONScriptBlock(t *testing.T) {
	body := `<html><body><script type="application/json">{"key": "nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "application/json script")
}

func TestDetectReflections_LDJSONScriptBlock(t *testing.T) {
	body := `<html><body><script type="application/ld+json">{"name": "nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "application/ld+json script")
}

func TestDetectReflections_ImportmapScriptBlock(t *testing.T) {
	body := `<html><body><script type="importmap">{"imports": {"nucleiXSScanary": "/mod.js"}}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "importmap script")
}

func TestDetectReflections_SpeculationrulesScriptBlock(t *testing.T) {
	body := `<html><body><script type="speculationrules">{"prerender": [{"source": "nucleiXSScanary"}]}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "speculationrules script")
}

func TestDetectReflections_TextPlainScriptBlock(t *testing.T) {
	body := `<html><body><script type="text/plain">nucleiXSScanary</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "text/plain script")
}

func TestDetectReflections_TextTemplateScriptBlock(t *testing.T) {
	body := `<html><body><script type="text/template"><div>nucleiXSScanary</div></script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "text/template script")
}

func TestDetectReflections_ExecutableScriptStillWorks(t *testing.T) {
	body := `<html><body><script>var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "regular script (no type) should be executable")
}

func TestDetectReflections_TextJavascriptType(t *testing.T) {
	body := `<html><body><script type="text/javascript">var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "text/javascript should be executable")
}

func TestDetectReflections_ModuleScriptType(t *testing.T) {
	body := `<html><body><script type="module">import nucleiXSScanary from './mod.js';</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "module type should be executable")
}

func TestDetectReflections_DataTypeAttrNotConfused(t *testing.T) {
	body := `<html><body><script data-type="application/json">var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "data-type attr must NOT affect script classification")
}

func TestDetectReflections_CustomTypeAttrNotConfused(t *testing.T) {
	body := `<html><body><script mytype="application/json">var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "mytype attr must NOT affect script classification")
}

func TestDetectReflections_UnknownScriptType(t *testing.T) {
	body := `<html><body><script type="text/x-handlebars-template">{{nucleiXSScanary}}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	assertNoExecutableScript(t, reflections, "unknown script type is a data block per WHATWG spec")
}

// ==================== Bug #7086 Fix 3: Case-insensitive reflection ====================

func TestDetectReflections_CaseSensitiveMarker_Uppercase(t *testing.T) {
	body := `<html><body><p>NUCLEIXSSCANARY</p></body></html>`
	reflections := DetectReflections(body, "nucleiXSScanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive detection for uppercase reflection")
	}
}

func TestDetectReflections_CaseSensitiveMarker_MixedCase(t *testing.T) {
	body := `<html><body><p>NuClEiXsSCaNaRy</p></body></html>`
	reflections := DetectReflections(body, "nucleiXSScanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive detection for mixed-case reflection")
	}
}

func TestDetectReflections_CaseSensitiveMarker_Lowercase(t *testing.T) {
	body := `<html><body><p>nucleixsscanary</p></body></html>`
	reflections := DetectReflections(body, "nucleiXSScanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive detection for lowercase reflection")
	}
}

// ==================== Bug #7086 Fix 4: srcdoc ====================

func TestDetectReflections_SrcdocAttribute(t *testing.T) {
	body := `<html><body><iframe srcdoc="<b>nucleiXSScanary</b>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContextAttr(t, reflections, ContextHTMLText, "srcdoc", "srcdoc allows full HTML injection")
}

func TestDetectReflections_SrcdocWithScript(t *testing.T) {
	body := `<html><body><iframe srcdoc="<script>nucleiXSScanary</script>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContextAttr(t, reflections, ContextHTMLText, "srcdoc", "srcdoc with script injection")
}

// ==================== data: URI detection ====================

func TestDetectReflections_DataTextHTMLURI(t *testing.T) {
	body := `<html><body><iframe src="data:text/html,<script>nucleiXSScanary</script>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "data:text/html URI is executable")
}

func TestDetectReflections_DataJavascriptURI(t *testing.T) {
	body := `<html><body><iframe src="data:text/javascript,alert(nucleiXSScanary)"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "data:text/javascript URI is executable")
}

func TestDetectReflections_DataSVGURI(t *testing.T) {
	body := `<html><body><embed src="data:image/svg+xml,<svg onload=nucleiXSScanary>"></embed></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "data:image/svg+xml URI is executable")
}

func TestDetectReflections_DataXHTMLURI(t *testing.T) {
	body := `<html><body><iframe src="data:application/xhtml+xml,<html xmlns='http://www.w3.org/1999/xhtml'><script>alert(nucleiXSScanary)</script></html>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextScript, "data:application/xhtml+xml URI is executable")
}

func TestDetectReflections_DataPlainTextURI(t *testing.T) {
	body := `<html><body><iframe src="data:text/plain,nucleiXSScanary"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	requireContext(t, reflections, ContextAttribute, "data:text/plain is not executable")
}

// ==================== BestReflection ====================

func TestBestReflection_Priority(t *testing.T) {
	reflections := []ReflectionInfo{
		{Context: ContextHTMLComment},
		{Context: ContextHTMLText},
		{Context: ContextAttribute},
		{Context: ContextScript},
	}
	best := BestReflection(reflections)
	if best == nil || best.Context != ContextScript {
		t.Fatal("expected ContextScript as highest priority")
	}
}

func TestBestReflection_SkipsNone(t *testing.T) {
	reflections := []ReflectionInfo{
		{Context: ContextNone},
		{Context: ContextHTMLText},
	}
	best := BestReflection(reflections)
	if best == nil || best.Context != ContextHTMLText {
		t.Fatal("BestReflection should skip ContextNone")
	}
}

func TestBestReflection_AllNone(t *testing.T) {
	reflections := []ReflectionInfo{
		{Context: ContextNone},
	}
	best := BestReflection(reflections)
	if best != nil {
		t.Fatal("expected nil when all reflections are ContextNone")
	}
}

func TestBestReflection_Empty(t *testing.T) {
	best := BestReflection(nil)
	if best != nil {
		t.Fatal("expected nil for empty reflections")
	}
}

// ==================== detectScriptStringContext ====================

func TestDetectScriptStringContext_NotInString(t *testing.T) {
	content := `var x = nucleiXSScanary;`
	ctx := detectScriptStringContext(content, testMarker)
	if ctx != ContextScript {
		t.Fatalf("expected ContextScript, got %s", ctx)
	}
}

func TestDetectScriptStringContext_InDoubleQuote(t *testing.T) {
	content := `var x = "nucleiXSScanary";`
	ctx := detectScriptStringContext(content, testMarker)
	if ctx != ContextScriptString {
		t.Fatalf("expected ContextScriptString, got %s", ctx)
	}
}

func TestDetectScriptStringContext_InSingleQuote(t *testing.T) {
	content := `var x = 'nucleiXSScanary';`
	ctx := detectScriptStringContext(content, testMarker)
	if ctx != ContextScriptString {
		t.Fatalf("expected ContextScriptString, got %s", ctx)
	}
}

func TestDetectScriptStringContext_EscapedQuote(t *testing.T) {
	content := `var x = "test\"nucleiXSScanary";`
	ctx := detectScriptStringContext(content, testMarker)
	if ctx != ContextScriptString {
		t.Fatalf("expected ContextScriptString for escaped quote, got %s", ctx)
	}
}

func TestDetectScriptStringContext_AfterClosedString(t *testing.T) {
	content := `var x = "test"; var y = nucleiXSScanary;`
	ctx := detectScriptStringContext(content, testMarker)
	if ctx != ContextScript {
		t.Fatalf("expected ContextScript after closed string, got %s", ctx)
	}
}

// ==================== isEventHandler ====================

func TestIsEventHandler(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"onclick", true},
		{"onload", true},
		{"onerror", true},
		{"onmouseover", true},
		{"ONCLICK", true},
		{"OnClick", true},
		{"class", false},
		{"href", false},
		{"style", false},
		{"data-onclick", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEventHandler(tt.name); got != tt.expected {
				t.Errorf("isEventHandler(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

// ==================== Context.String() ====================

func TestContextString(t *testing.T) {
	tests := []struct {
		ctx      Context
		expected string
	}{
		{ContextNone, "none"},
		{ContextHTMLComment, "html_comment"},
		{ContextHTMLText, "html_text"},
		{ContextAttribute, "attribute"},
		{ContextAttributeUnquoted, "attribute_unquoted"},
		{ContextScript, "script"},
		{ContextScriptString, "script_string"},
		{ContextStyle, "style"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.ctx.String(); got != tt.expected {
				t.Errorf("Context.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ==================== selectPayloads ====================

func TestSelectPayloads(t *testing.T) {
	tests := []struct {
		name       string
		reflection ReflectionInfo
		chars      CharacterSet
		wantEmpty  bool
	}{
		{
			name:       "HTML text with angle brackets",
			reflection: ReflectionInfo{Context: ContextHTMLText},
			chars:      CharacterSet{LessThan: true, GreaterThan: true},
			wantEmpty:  false,
		},
		{
			name:       "HTML text without angle brackets",
			reflection: ReflectionInfo{Context: ContextHTMLText},
			chars:      CharacterSet{},
			wantEmpty:  true,
		},
		{
			name:       "Double-quoted attribute with quotes",
			reflection: ReflectionInfo{Context: ContextAttribute, QuoteChar: '"'},
			chars:      CharacterSet{DoubleQuote: true},
			wantEmpty:  false,
		},
		{
			name:       "Script context",
			reflection: ReflectionInfo{Context: ContextScript},
			chars:      CharacterSet{},
			wantEmpty:  false,
		},
		{
			name:       "Script string with single quote",
			reflection: ReflectionInfo{Context: ContextScriptString},
			chars:      CharacterSet{SingleQuote: true},
			wantEmpty:  false,
		},
		{
			name:       "Comment context",
			reflection: ReflectionInfo{Context: ContextHTMLComment},
			chars:      CharacterSet{},
			wantEmpty:  false,
		},
		{
			name:       "Style context",
			reflection: ReflectionInfo{Context: ContextStyle},
			chars:      CharacterSet{},
			wantEmpty:  false,
		},
		{
			name:       "Unquoted attribute",
			reflection: ReflectionInfo{Context: ContextAttributeUnquoted},
			chars:      CharacterSet{},
			wantEmpty:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := selectPayloads(&tt.reflection, tt.chars)
			if tt.wantEmpty && len(payloads) > 0 {
				t.Errorf("expected no payloads, got %d", len(payloads))
			}
			if !tt.wantEmpty && len(payloads) == 0 {
				t.Error("expected payloads but got none")
			}
		})
	}
}

// ==================== detectCharacterSurvival ====================

func TestDetectCharacterSurvival(t *testing.T) {
	canary := "testcanary"
	body := canary + "<" + canary + ">" + canary + `"` + canary + "'" + canary + "/"
	chars := detectCharacterSurvival(body, canary)
	if !chars.LessThan {
		t.Error("expected LessThan to survive")
	}
	if !chars.GreaterThan {
		t.Error("expected GreaterThan to survive")
	}
	if !chars.DoubleQuote {
		t.Error("expected DoubleQuote to survive")
	}
	if !chars.SingleQuote {
		t.Error("expected SingleQuote to survive")
	}
	if !chars.ForwardSlash {
		t.Error("expected ForwardSlash to survive")
	}
}

func TestDetectCharacterSurvival_Encoded(t *testing.T) {
	canary := "testcanary"
	body := canary + `&lt;&gt;&quot;&#39;/`
	chars := detectCharacterSurvival(body, canary)
	if chars.LessThan {
		t.Error("expected LessThan to be encoded")
	}
	if chars.GreaterThan {
		t.Error("expected GreaterThan to be encoded")
	}
}

func TestDetectCharacterSurvival_Independent(t *testing.T) {
	canary := "testcanary"
	body := canary + "&lt;" + canary + ">" + canary + `"` + canary + "'"
	chars := detectCharacterSurvival(body, canary)
	if chars.LessThan {
		t.Error("< is encoded, should be false")
	}
	if !chars.GreaterThan {
		t.Error("> survives, should be true")
	}
	if !chars.DoubleQuote {
		t.Error(`" survives, should be true`)
	}
	if !chars.SingleQuote {
		t.Error("' survives, should be true")
	}
}

// ==================== isHTMLResponse / hasCSP ====================

func TestIsHTMLResponse(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected bool
	}{
		{"nil headers", nil, true},
		{"empty headers", map[string][]string{}, true},
		{"text/html", map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}, true},
		{"application/xhtml", map[string][]string{"Content-Type": {"application/xhtml+xml"}}, true},
		{"application/json", map[string][]string{"Content-Type": {"application/json"}}, false},
		{"text/plain", map[string][]string{"Content-Type": {"text/plain"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHTMLResponse(tt.headers); got != tt.expected {
				t.Errorf("isHTMLResponse() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasCSP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected bool
	}{
		{"no CSP", map[string][]string{}, false},
		{"has CSP", map[string][]string{"Content-Security-Policy": {"default-src 'self'"}}, true},
		{"nil headers", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasCSP(tt.headers); got != tt.expected {
				t.Errorf("hasCSP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ==================== isExecutableScriptTag ====================

func TestIsExecutableScriptTag(t *testing.T) {
	tests := []struct {
		rawToken string
		expected bool
	}{
		{`<script>`, true},
		{`<script type="text/javascript">`, true},
		{`<script type="module">`, true},
		{`<script type="application/javascript">`, true},
		{`<script type="text/ecmascript">`, true},
		{`<script type="application/json">`, false},
		{`<script type="application/ld+json">`, false},
		{`<script type="importmap">`, false},
		{`<script type="speculationrules">`, false},
		{`<script type="text/plain">`, false},
		{`<script type="text/template">`, false},
		{`<script type="text/html">`, false},
		{`<script type="text/x-handlebars-template">`, false},
		{`<script data-type="application/json">`, true},
		{`<script mytype="application/json">`, true},
		{`<script type = "application/json">`, false},
		{`<SCRIPT TYPE="APPLICATION/JSON">`, false},
		{`<script type="text/javascript; charset=utf-8">`, true},
		{`<script type="application/javascript;charset=utf-8">`, true},
		{`<script type="application/json; charset=utf-8">`, false},
	}
	for _, tt := range tests {
		t.Run(tt.rawToken, func(t *testing.T) {
			if got := isExecutableScriptTag(tt.rawToken); got != tt.expected {
				t.Errorf("isExecutableScriptTag(%q) = %v, want %v", tt.rawToken, got, tt.expected)
			}
		})
	}
}

// ==================== isJavascriptURI ====================

func TestIsJavascriptURI(t *testing.T) {
	tests := []struct {
		val      string
		expected bool
	}{
		{"javascript:alert(1)", true},
		{"JavaScript:alert(1)", true},
		{"JAVASCRIPT:alert(1)", true},
		{"  javascript:alert(1)", true},
		{"\tjavascript:alert(1)", true},
		{"https://example.com", false},
		{"java script:alert(1)", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			if got := isJavascriptURI(tt.val); got != tt.expected {
				t.Errorf("isJavascriptURI(%q) = %v, want %v", tt.val, got, tt.expected)
			}
		})
	}
}

// ==================== isDataExecutableURI ====================

func TestIsDataExecutableURI(t *testing.T) {
	tests := []struct {
		val      string
		expected bool
	}{
		{"data:text/html,<script>alert(1)</script>", true},
		{"data:text/javascript,alert(1)", true},
		{"data:application/javascript,alert(1)", true},
		{"data:image/svg+xml,<svg onload=alert(1)>", true},
		{"data:application/xhtml+xml,<html><script>alert(1)</script></html>", true},
		{"data:text/plain,hello", false},
		{"data:application/json,{}", false},
		{"https://example.com", false},
		{"data:", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			if got := isDataExecutableURI(tt.val); got != tt.expected {
				t.Errorf("isDataExecutableURI(%q) = %v, want %v", tt.val, got, tt.expected)
			}
		})
	}
}

// ==================== detectAttrQuoting ====================

func TestDetectAttrQuoting(t *testing.T) {
	tests := []struct {
		rawToken  string
		attrName  string
		wantQuote byte
		wantUnq   bool
	}{
		{`<input value="test">`, "value", '"', false},
		{`<input value='test'>`, "value", '\'', false},
		{`<input value=test>`, "value", 0, true},
		{`<input value = "test">`, "value", '"', false},
		{`<input value = 'test'>`, "value", '\'', false},
		{`<input data-value="test" value='real'>`, "value", '\'', false},
	}
	for _, tt := range tests {
		t.Run(tt.rawToken, func(t *testing.T) {
			quote, unq := detectAttrQuoting(tt.rawToken, tt.attrName)
			if quote != tt.wantQuote || unq != tt.wantUnq {
				t.Errorf("detectAttrQuoting(%q, %q) = (%c, %v), want (%c, %v)",
					tt.rawToken, tt.attrName, quote, unq, tt.wantQuote, tt.wantUnq)
			}
		})
	}
}

// ==================== Benchmarks ====================

func BenchmarkDetectReflections(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf("<div class='item-%d'>Content %d</div>", i, i))
	}
	sb.WriteString("<p>nucleiXSScanary</p>")
	sb.WriteString("</body></html>")
	body := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, testMarker)
	}
}

func BenchmarkDetectReflections_LargeBody(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < 1000; i++ {
		sb.WriteString(fmt.Sprintf(`<div id="item-%d"><a href="/page/%d">Link %d</a><span class="data">Data %d</span></div>`, i, i, i, i))
	}
	sb.WriteString(`<input value="nucleiXSScanary">`)
	sb.WriteString("</body></html>")
	body := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, testMarker)
	}
}

// ==================== Test helpers ====================

func requireContext(t *testing.T, reflections []ReflectionInfo, expected Context, desc string) {
	t.Helper()
	if len(reflections) == 0 {
		t.Fatalf("%s: expected reflections, got none", desc)
	}
	for _, r := range reflections {
		if r.Context == expected {
			return
		}
	}
	t.Fatalf("%s: expected %s in reflections, got %v", desc, expected, reflections)
}

func requireContextAttr(t *testing.T, reflections []ReflectionInfo, expected Context, attrName, desc string) {
	t.Helper()
	if len(reflections) == 0 {
		t.Fatalf("%s: expected reflections, got none", desc)
	}
	for _, r := range reflections {
		if r.Context == expected && r.AttrName == attrName {
			return
		}
	}
	t.Fatalf("%s: expected %s for attr %q, got %v", desc, expected, attrName, reflections)
}

func assertNoExecutableScript(t *testing.T, reflections []ReflectionInfo, desc string) {
	t.Helper()
	for _, r := range reflections {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Fatalf("%s: should NOT be classified as executable script, got %s", desc, r.Context)
		}
	}
}
