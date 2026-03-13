package xss

import (
	"fmt"
	"strings"
	"testing"
)

const testMarker = "nucleiXSScanary"

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

func TestBestReflection_Empty(t *testing.T) {
	best := BestReflection(nil)
	if best != nil {
		t.Fatal("expected nil for empty reflections")
	}
}

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

func TestDetectCharacterSurvival(t *testing.T) {
	canary := "testcanary"
	body := canary + `<>"'/`
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

// ---- Regression tests for issue #7086 ----

// Fix #1: javascript: URI scheme in href/src/action should be ContextScript
func TestDetectReflections_JavascriptURI_Href(t *testing.T) {
	body := `<html><body><a href="javascript:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection for javascript: URI in href")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "href" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for javascript: URI in href, got %v", reflections)
	}
}

func TestDetectReflections_JavascriptURI_Src(t *testing.T) {
	body := `<html><body><iframe src="javascript:nucleiXSScanary"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection for javascript: URI in src")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "src" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for javascript: URI in src, got %v", reflections)
	}
}

func TestDetectReflections_JavascriptURI_CaseInsensitive(t *testing.T) {
	body := `<html><body><a href="JAVASCRIPT:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection for JAVASCRIPT: URI (uppercase scheme)")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for JAVASCRIPT: URI, got %v", reflections)
	}
}

// Fix #2: <script type="application/json"> should NOT be ContextScript
func TestDetectReflections_JsonScriptBlock_NotExecutable(t *testing.T) {
	body := `<html><body><script type="application/json">{"key":"nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	// If reflected, it must NOT be ContextScript or ContextScriptString
	for _, r := range reflections {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Fatalf("expected non-script context for application/json script block, got %s", r.Context)
		}
	}
}

func TestDetectReflections_LdJsonScriptBlock_NotExecutable(t *testing.T) {
	body := `<html><body><script type="application/ld+json">{"@context":"nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	for _, r := range reflections {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Fatalf("expected non-script context for application/ld+json script block, got %s", r.Context)
		}
	}
}

func TestDetectReflections_ExecutableScriptBlock(t *testing.T) {
	// Sanity: regular <script> (no type attr) must still be ContextScript
	body := `<html><body><script>var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in executable script block")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("expected ContextScript for executable script block, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_TextJavascriptScriptBlock(t *testing.T) {
	// Sanity: <script type="text/javascript"> must still be ContextScript
	body := `<html><body><script type="text/javascript">var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in text/javascript script block")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("expected ContextScript for text/javascript script block, got %s", reflections[0].Context)
	}
}

// Fix #3: reflection detection should be case-insensitive
func TestDetectReflections_CaseInsensitiveMarker(t *testing.T) {
	// Marker is lowercase but response has uppercase version
	body := `<html><body><p>NUCLEIXSSCANARY</p></body></html>`
	reflections := DetectReflections(body, "nucleixsscanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive reflection detection (uppercase in body, lowercase marker)")
	}
	if reflections[0].Context != ContextHTMLText {
		t.Fatalf("expected ContextHTMLText for case-insensitive reflection, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_CaseInsensitiveMixedCase(t *testing.T) {
	body := `<html><body><input value="NuClEiXsSCaNaRy"></body></html>`
	reflections := DetectReflections(body, "nucleixsscanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive reflection detection (mixed case in attribute)")
	}
}

// Fix #4: srcdoc attribute should be ContextHTMLText
func TestDetectReflections_Srcdoc(t *testing.T) {
	body := `<html><body><iframe srcdoc="<p>nucleiXSScanary</p>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in srcdoc attribute")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextHTMLText && r.AttrName == "srcdoc" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextHTMLText for srcdoc attribute, got %v", reflections)
	}
}

func TestIsNonExecutableScriptType(t *testing.T) {
	tests := []struct {
		typeAttr string
		expected bool
	}{
		{"application/json", true},
		{"application/ld+json", true},
		{"application/json; charset=utf-8", true},
		{"  application/json  ", true},
		{"text/javascript", false},
		{"", false},
		{"module", false},
		{"application/javascript", false},
	}
	for _, tt := range tests {
		t.Run(tt.typeAttr, func(t *testing.T) {
			if got := isNonExecutableScriptType(tt.typeAttr); got != tt.expected {
				t.Errorf("isNonExecutableScriptType(%q) = %v, want %v", tt.typeAttr, got, tt.expected)
			}
		})
	}
}

func TestIsJavaScriptURI(t *testing.T) {
	tests := []struct {
		attrVal  string
		expected bool
	}{
		{"javascript:alert(1)", true},
		{"JAVASCRIPT:alert(1)", true},
		{"JavaScript:alert(1)", true},
		{"  javascript:alert(1)", true}, // leading whitespace
		{"https://example.com", false},
		{"http://example.com", false},
		{"data:text/html,<h1>test</h1>", false},
		{"/path/to/page", false},
	}
	for _, tt := range tests {
		t.Run(tt.attrVal, func(t *testing.T) {
			if got := isJavaScriptURI(tt.attrVal); got != tt.expected {
				t.Errorf("isJavaScriptURI(%q) = %v, want %v", tt.attrVal, got, tt.expected)
			}
		})
	}
}

// ---- End regression tests for issue #7086 ----

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
