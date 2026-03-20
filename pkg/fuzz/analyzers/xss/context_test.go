package xss

import (
	"fmt"
	"strings"
	"testing"
)

const testMarker = "nucleiXSScanary"

// -----------------------------------------------------------------------
// Existing context detection tests (unchanged from PR #7076)
// -----------------------------------------------------------------------

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

func TestDetectReflections_TagNameReflection(t *testing.T) {
	body := `<html><body><nucleiXSScanary>test</nucleiXSScanary></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in tag name")
	}
}

// -----------------------------------------------------------------------
// Regression tests for issue #7086
// -----------------------------------------------------------------------

// FIX 1: javascript: URIs must be classified as ContextScript

func TestDetectReflections_JavascriptURI_Href(t *testing.T) {
	body := `<html><body><a href="javascript:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in javascript: URI")
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

func TestDetectReflections_JavascriptURI_MixedCase(t *testing.T) {
	body := `<html><body><a href="JavaScript:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "href" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for mixed-case JavaScript: URI, got %v", reflections)
	}
}

func TestDetectReflections_JavascriptURI_LeadingWhitespace(t *testing.T) {
	body := `<html><body><a href="  javascript:nucleiXSScanary">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "href" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for javascript: URI with leading whitespace, got %v", reflections)
	}
}

func TestDetectReflections_JavascriptURI_FormAction(t *testing.T) {
	body := `<html><body><form><button formaction="javascript:nucleiXSScanary">go</button></form></body></html>`
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

func TestDetectReflections_NonJavascriptURI_Href(t *testing.T) {
	// Regular URL in href should stay as ContextAttribute, not ContextScript
	body := `<html><body><a href="https://nucleiXSScanary.example.com">click</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in href")
	}
	for _, r := range reflections {
		if r.AttrName == "href" && r.Context == ContextScript {
			t.Fatal("non-javascript: href should not be classified as ContextScript")
		}
	}
}

// FIX 2: Non-executable <script type="application/json"> blocks

func TestDetectReflections_ScriptJSON(t *testing.T) {
	body := `<html><body><script type="application/json">{"key":"nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in JSON script block")
	}
	if reflections[0].Context != ContextScriptData {
		t.Fatalf("expected ContextScriptData for application/json, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptLDJSON(t *testing.T) {
	body := `<html><head><script type="application/ld+json">{"name":"nucleiXSScanary"}</script></head></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in LD+JSON script block")
	}
	if reflections[0].Context != ContextScriptData {
		t.Fatalf("expected ContextScriptData for application/ld+json, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptJSONWithCharset(t *testing.T) {
	body := `<html><body><script type="application/json; charset=utf-8">{"key":"nucleiXSScanary"}</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in JSON script block with charset")
	}
	if reflections[0].Context != ContextScriptData {
		t.Fatalf("expected ContextScriptData for application/json with charset, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptTextJavascript(t *testing.T) {
	// text/javascript is executable — should still be ContextScript
	body := `<html><body><script type="text/javascript">var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in text/javascript script block")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("expected ContextScript for text/javascript, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptNoType(t *testing.T) {
	// No type attribute = executable JavaScript
	body := `<html><body><script>var x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in script with no type")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("expected ContextScript for script with no type, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_ScriptModule(t *testing.T) {
	// type="module" is executable
	body := `<html><body><script type="module">const x = nucleiXSScanary;</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection in module script")
	}
	if reflections[0].Context != ContextScript {
		t.Fatalf("expected ContextScript for module type, got %s", reflections[0].Context)
	}
}

// FIX 3: Case-insensitive reflection detection

func TestDetectReflections_CaseInsensitive(t *testing.T) {
	body := `<html><body><p>NUCLEIxssCANARY</p></body></html>`
	reflections := DetectReflections(body, "nucleixsscanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive reflection detection")
	}
}

func TestDetectReflections_CaseInsensitive_MixedMarker(t *testing.T) {
	// Server lowercases the entire body including our canary
	body := `<html><body><p>nucleixsscanary</p></body></html>`
	reflections := DetectReflections(body, "nucleiXSScanary")
	if len(reflections) == 0 {
		t.Fatal("expected case-insensitive match when server lowercases response")
	}
}

func TestDetectCharacterSurvival_CaseInsensitive(t *testing.T) {
	canary := "NuClEiCanary"
	// Server lowercases the canary but preserves special chars
	body := `nucleicanary<>"'/`
	chars := detectCharacterSurvival(body, canary)
	if !chars.LessThan {
		t.Error("expected LessThan to survive (case-insensitive)")
	}
	if !chars.GreaterThan {
		t.Error("expected GreaterThan to survive (case-insensitive)")
	}
	if !chars.DoubleQuote {
		t.Error("expected DoubleQuote to survive (case-insensitive)")
	}
	if !chars.SingleQuote {
		t.Error("expected SingleQuote to survive (case-insensitive)")
	}
	if !chars.ForwardSlash {
		t.Error("expected ForwardSlash to survive (case-insensitive)")
	}
}

func TestDetectCharacterSurvival_PartialEncoding(t *testing.T) {
	canary := "testcanary"
	// Only < and > are encoded, quotes and / survive
	body := canary + `&lt;&gt;"'/`
	chars := detectCharacterSurvival(body, canary)
	if chars.LessThan {
		t.Error("expected LessThan to be encoded")
	}
	if chars.GreaterThan {
		t.Error("expected GreaterThan to be encoded")
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

// FIX 4: srcdoc attributes

func TestDetectReflections_Srcdoc(t *testing.T) {
	body := `<html><body><iframe srcdoc="nucleiXSScanary"></iframe></body></html>`
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

func TestDetectReflections_Srcdoc_WithHTML(t *testing.T) {
	body := `<html><body><iframe srcdoc="<p>nucleiXSScanary</p>"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	found := false
	for _, r := range reflections {
		if r.Context == ContextHTMLText && r.AttrName == "srcdoc" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextHTMLText for srcdoc with embedded HTML, got %v", reflections)
	}
}

// -----------------------------------------------------------------------
// Helper function tests
// -----------------------------------------------------------------------

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

func TestBestReflection_SkipsNone(t *testing.T) {
	reflections := []ReflectionInfo{
		{Context: ContextNone},
		{Context: ContextHTMLText},
	}
	best := BestReflection(reflections)
	if best == nil || best.Context != ContextHTMLText {
		t.Fatal("expected BestReflection to skip ContextNone")
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

func TestIsExecutableScriptType(t *testing.T) {
	tests := []struct {
		scriptType string
		expected   bool
	}{
		{"", true},                            // no type = executable
		{"text/javascript", true},             // standard JS
		{"application/javascript", true},      // legacy JS
		{"module", true},                      // ES module
		{"TEXT/JAVASCRIPT", true},             // case insensitive
		{"text/javascript; charset=utf-8", true}, // with MIME params
		{"application/json", false},           // data
		{"application/ld+json", false},        // structured data
		{"text/html", false},                  // not JS
		{"application/xml", false},            // not JS
	}

	for _, tt := range tests {
		t.Run(tt.scriptType, func(t *testing.T) {
			if got := isExecutableScriptType(tt.scriptType); got != tt.expected {
				t.Errorf("isExecutableScriptType(%q) = %v, want %v", tt.scriptType, got, tt.expected)
			}
		})
	}
}

func TestIsJavascriptURI(t *testing.T) {
	tests := []struct {
		val      string
		expected bool
	}{
		{"javascript:alert(1)", true},
		{"JavaScript:alert(1)", true},
		{"JAVASCRIPT:alert(1)", true},
		{"  javascript:alert(1)", true},       // leading whitespace
		{"\tjavascript:alert(1)", true},       // leading tab
		{"https://example.com", false},
		{"http://example.com", false},
		{"data:text/html,<h1>hi</h1>", false}, // not javascript:
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

func TestDetectAttrQuoting_WithWhitespace(t *testing.T) {
	// Handles attr = "value" with spaces around =
	raw := `<input value = "test">`
	quote, unquoted := detectAttrQuoting(raw, "value")
	if quote != '"' || unquoted {
		t.Fatalf("expected double-quoted, got quote=%c unquoted=%v", quote, unquoted)
	}
}

func TestDetectAttrQuoting_NoSpace(t *testing.T) {
	raw := `<input value="test">`
	quote, unquoted := detectAttrQuoting(raw, "value")
	if quote != '"' || unquoted {
		t.Fatalf("expected double-quoted, got quote=%c unquoted=%v", quote, unquoted)
	}
}

func TestDetectAttrQuoting_SingleQuote(t *testing.T) {
	raw := `<input value='test'>`
	quote, unquoted := detectAttrQuoting(raw, "value")
	if quote != '\'' || unquoted {
		t.Fatalf("expected single-quoted, got quote=%c unquoted=%v", quote, unquoted)
	}
}

func TestDetectAttrQuoting_Unquoted(t *testing.T) {
	raw := `<input value=test>`
	_, unquoted := detectAttrQuoting(raw, "value")
	if !unquoted {
		t.Fatal("expected unquoted attribute")
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
		{ContextScriptData, "script_data"},
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
		{
			name:       "Script data (JSON) — breakout payload",
			reflection: ReflectionInfo{Context: ContextScriptData},
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

// -----------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------

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
