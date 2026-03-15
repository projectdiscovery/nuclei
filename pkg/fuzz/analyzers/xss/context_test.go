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
	// Each character appears individually after the canary so they can be
	// detected independently (no cascading dependency).
	body := canary + `<` + " " + canary + `>` + " " + canary + `"` + " " + canary + `'` + " " + canary + `/`
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

// === Tests for issue #7086 fixes ===

// Fix 1: javascript: URIs should be classified as ContextScript, not ContextAttribute
func TestDetectReflections_JavascriptURI(t *testing.T) {
	body := `<html><body><a href="javascript:alert(nucleiXSScanary)">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in javascript: URI")
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

func TestDetectReflections_JavascriptURI_FormAction(t *testing.T) {
	body := `<html><body><form formaction="javascript:nucleiXSScanary"><input></form></body></html>`
	reflections := DetectReflections(body, testMarker)
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "formaction" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for javascript: URI in formaction, got %v", reflections)
	}
}

func TestDetectReflections_NonJavascriptHref(t *testing.T) {
	// Regular href should still be ContextAttribute
	body := `<html><body><a href="https://example.com/nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection")
	}
	for _, r := range reflections {
		if r.AttrName == "href" && r.Context == ContextScript {
			t.Fatal("non-javascript: href should not be ContextScript")
		}
	}
}

// Fix 2: <script type="application/json"> should not be treated as executable
func TestDetectReflections_ScriptTypeJSON(t *testing.T) {
	body := `<html><body><script type="application/json">{"key": "nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in JSON script block")
	}
	for _, r := range reflections {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Fatalf("application/json script should not be classified as executable script context, got %s", r.Context)
		}
	}
	if reflections[0].Context != ContextNonExecutableScript {
		t.Fatalf("expected ContextNonExecutableScript for JSON script block, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptTypeLDJSON(t *testing.T) {
	body := `<html><head><script type="application/ld+json">{"name": "nucleiXSScanary"}</script></head></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in ld+json script")
	}
	if reflections[0].Context == ContextScript || reflections[0].Context == ContextScriptString {
		t.Fatal("ld+json script should not be classified as executable")
	}
}

func TestDetectReflections_ScriptTypeImportmap(t *testing.T) {
	body := `<html><head><script type="importmap">{"imports": {"nucleiXSScanary": "/mod.js"}}</script></head></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in importmap script")
	}
	if reflections[0].Context == ContextScript || reflections[0].Context == ContextScriptString {
		t.Fatal("importmap script should not be classified as executable")
	}
}

func TestDetectReflections_ScriptNoType(t *testing.T) {
	// Regular <script> without type should still be executable
	body := `<html><body><script>var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in regular script")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("regular script should be ContextScript, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptTypeJavascript(t *testing.T) {
	// <script type="text/javascript"> is still executable
	body := `<html><body><script type="text/javascript">var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in text/javascript script")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("text/javascript script should be ContextScript, got %s", reflections[0].Context)
	}
}

// Fix 3: Case-insensitive reflection detection at the top-level check
func TestDetectReflections_CaseInsensitiveInitialCheck(t *testing.T) {
	// The marker is "nucleiXSScanary" but reflected as "NUCLEIXSSCANARY"
	body := `<html><body><p>NUCLEIXSSCANARY</p></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive initial check to find upper-case reflection")
	}
}

func TestDetectReflections_CaseInsensitiveMixedCase(t *testing.T) {
	body := `<html><body><input value="NuClEiXsScAnArY"></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive detection for mixed case reflection")
	}
}

// Fix 4: srcdoc should be treated as HTML injection context
func TestDetectReflections_SrcdocAttribute(t *testing.T) {
	body := `<html><body><iframe srcdoc="<p>nucleiXSScanary</p>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in srcdoc attribute")
	}
	found := false
	for _, r := range reflections {
		if r.AttrName == "srcdoc" && r.Context == ContextHTMLText {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextHTMLText for srcdoc, got %v", reflections)
	}
}

// === Helper function tests ===

func TestIsJavascriptURI(t *testing.T) {
	tests := []struct {
		attr     string
		val      string
		expected bool
	}{
		{"href", "javascript:alert(1)", true},
		{"href", "JavaScript:alert(1)", true},
		{"href", "  javascript:alert(1)", true},
		{"src", "javascript:void(0)", true},
		{"action", "javascript:submit()", true},
		{"href", "https://example.com", false},
		{"href", "", false},
		{"class", "javascript:alert(1)", false}, // not a URI attribute
		{"title", "javascript:alert(1)", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s=%s", tt.attr, tt.val), func(t *testing.T) {
			if got := isJavascriptURI(tt.attr, tt.val); got != tt.expected {
				t.Errorf("isJavascriptURI(%q, %q) = %v, want %v", tt.attr, tt.val, got, tt.expected)
			}
		})
	}
}

func TestIsNonExecutableScriptType(t *testing.T) {
	tests := []struct {
		rawToken string
		expected bool
	}{
		{`<script type="application/json">`, true},
		{`<script type="application/ld+json">`, true},
		{`<script type="importmap">`, true},
		{`<script type="text/javascript">`, false},
		{`<script type="module">`, false},
		{`<script>`, false},
		{`<script type='application/json'>`, true},
		{`<script TYPE="application/json">`, true},
	}
	for _, tt := range tests {
		t.Run(tt.rawToken, func(t *testing.T) {
			if got := isNonExecutableScriptType(tt.rawToken); got != tt.expected {
				t.Errorf("isNonExecutableScriptType(%q) = %v, want %v", tt.rawToken, got, tt.expected)
			}
		})
	}
}

// === Tests for Finding #3: JavaScript comment and regex literal detection ===

func TestDetectScriptStringContext_LineComment(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    Context
	}{
		{
			name:    "marker in line comment",
			content: "var x = 1; // nucleiXSScanary",
			want:    ContextScriptComment,
		},
		{
			name:    "marker after line comment on next line",
			content: "// comment\nvar x = nucleiXSScanary;",
			want:    ContextScript,
		},
		{
			name:    "marker in line comment after code",
			content: "var x = 'safe'; // here is nucleiXSScanary",
			want:    ContextScriptComment,
		},
		{
			name:    "slash in string not a comment",
			content: `var x = "//not a comment"; var y = nucleiXSScanary;`,
			want:    ContextScript,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectScriptStringContext(tt.content, testMarker)
			if got != tt.want {
				t.Errorf("detectScriptStringContext() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDetectScriptStringContext_BlockComment(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    Context
	}{
		{
			name:    "marker in block comment",
			content: "var x = 1; /* nucleiXSScanary */",
			want:    ContextScriptComment,
		},
		{
			name:    "marker in multiline block comment",
			content: "var x = 1;\n/* this is a\nnucleiXSScanary\ncomment */",
			want:    ContextScriptComment,
		},
		{
			name:    "marker after closed block comment",
			content: "/* comment */ var x = nucleiXSScanary;",
			want:    ContextScript,
		},
		{
			name:    "marker in string after block comment",
			content: "/* comment */ var x = 'nucleiXSScanary';",
			want:    ContextScriptString,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectScriptStringContext(tt.content, testMarker)
			if got != tt.want {
				t.Errorf("detectScriptStringContext() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDetectScriptStringContext_RegexLiteral(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    Context
	}{
		{
			name:    "marker in regex literal after assignment",
			content: "var re = /nucleiXSScanary/;",
			want:    ContextScriptComment,
		},
		{
			name:    "marker in regex after return",
			content: "return /nucleiXSScanary/g;",
			want:    ContextScriptComment,
		},
		{
			name:    "division not regex",
			content: "var x = a / b; var y = nucleiXSScanary;",
			want:    ContextScript,
		},
		{
			name:    "regex in condition",
			content: "if (/nucleiXSScanary/.test(s)) {}",
			want:    ContextScriptComment,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectScriptStringContext(tt.content, testMarker)
			if got != tt.want {
				t.Errorf("detectScriptStringContext() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDetectReflections_ScriptLineComment(t *testing.T) {
	body := `<html><body><script>var x = "safe"; // nucleiXSScanary here</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if reflections[0].Context != ContextScriptComment {
		t.Fatalf("expected ContextScriptComment, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptBlockComment(t *testing.T) {
	body := `<html><body><script>/* nucleiXSScanary */ var x = 1;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if reflections[0].Context != ContextScriptComment {
		t.Fatalf("expected ContextScriptComment, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptRegexLiteral(t *testing.T) {
	body := `<html><body><script>var re = /nucleiXSScanary/g;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if reflections[0].Context != ContextScriptComment {
		t.Fatalf("expected ContextScriptComment for regex literal, got %s", reflections[0].Context)
	}
}

func TestSelectPayloads_ScriptComment(t *testing.T) {
	// Script comment with angle brackets should allow </script> breakout
	reflection := ReflectionInfo{Context: ContextScriptComment}
	chars := CharacterSet{LessThan: true, GreaterThan: true}
	payloads := selectPayloads(&reflection, chars)
	if len(payloads) == 0 {
		t.Fatal("expected payloads for script comment with angle brackets")
	}

	// Without angle brackets, no payloads (comment injection is not exploitable)
	chars2 := CharacterSet{}
	payloads2 := selectPayloads(&reflection, chars2)
	if len(payloads2) != 0 {
		t.Fatalf("expected no payloads for script comment without angle brackets, got %d", len(payloads2))
	}
}

func TestContextScriptComment_String(t *testing.T) {
	if got := ContextScriptComment.String(); got != "script_comment" {
		t.Errorf("ContextScriptComment.String() = %q, want %q", got, "script_comment")
	}
}

func TestContextScriptComment_Priority(t *testing.T) {
	// Script comment should have lower priority than executable script contexts
	if ContextScriptComment.priority() >= ContextScript.priority() {
		t.Error("ContextScriptComment should have lower priority than ContextScript")
	}
	if ContextScriptComment.priority() >= ContextScriptString.priority() {
		t.Error("ContextScriptComment should have lower priority than ContextScriptString")
	}
}

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
