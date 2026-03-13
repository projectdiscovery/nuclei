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

func TestDetectReflections_AttributeQuotingDoesNotMatchAttributeSubstring(t *testing.T) {
	body := `<html><body><div dataclass="a" class='nucleiXSScanary'></div></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in class attribute")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextAttribute && r.AttrName == "class" && r.QuoteChar == '\'' {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected class attribute to be detected as single-quoted, got %v", reflections)
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

func TestDetectReflections_JavascriptURI(t *testing.T) {
	body := `<html><body><a href="javascript:alert(nucleiXSScanary)">test</a></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in javascript URI")
	}
	found := false
	for _, r := range reflections {
		if r.Context == ContextScript && r.AttrName == "href" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ContextScript for href javascript URI, got %v", reflections)
	}
}

func TestDetectReflections_JavascriptURI_NonScriptURLAttribute(t *testing.T) {
	body := `<html><body><div data-url="javascript:alert(nucleiXSScanary)">test</div></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in data-url attribute")
	}
	for _, r := range reflections {
		if r.AttrName == "data-url" && r.Context == ContextScript {
			t.Fatalf("expected data-url javascript URI to stay non-script, got %v", reflections)
		}
	}
}

func TestDetectReflections_ScriptURIWhitespaceAndLegacySchemes(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{
			name: "javascript tab obfuscation",
			body: "<html><body><a href=\"java\tscript:alert(nucleiXSScanary)\">test</a></body></html>",
		},
		{
			name: "javascript newline obfuscation",
			body: "<html><body><a href=\"java\nscript:alert(nucleiXSScanary)\">test</a></body></html>",
		},
		{
			name: "vbscript scheme",
			body: `<html><body><a href="vbscript:msgbox(nucleiXSScanary)">test</a></body></html>`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reflections := DetectReflections(tc.body, testMarker)
			if len(reflections) == 0 {
				t.Fatalf("expected at least one reflection for %s", tc.name)
			}

			found := false
			for _, r := range reflections {
				if r.AttrName == "href" && r.Context == ContextScript {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected ContextScript for %s, got %v", tc.name, reflections)
			}
		})
	}
}

func TestDetectReflections_DataURIExecutableMIME(t *testing.T) {
	testCases := []struct {
		name         string
		body         string
		attrName     string
		expectScript bool
	}{
		{
			name:         "data html in href",
			body:         `<html><body><a href="data:text/html,<script>alert(nucleiXSScanary)</script>">test</a></body></html>`,
			attrName:     "href",
			expectScript: true,
		},
		{
			name:         "data html base64 in iframe src",
			body:         `<html><body><iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==#nucleiXSScanary"></iframe></body></html>`,
			attrName:     "src",
			expectScript: true,
		},
		{
			name:         "data png in img src",
			body:         `<html><body><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA#nucleiXSScanary"></body></html>`,
			attrName:     "src",
			expectScript: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reflections := DetectReflections(tc.body, testMarker)
			if len(reflections) == 0 {
				t.Fatalf("expected at least one reflection for %s", tc.name)
			}

			found := false
			for _, r := range reflections {
				if r.AttrName != tc.attrName {
					continue
				}
				found = true
				if tc.expectScript && r.Context != ContextScript {
					t.Fatalf("expected ContextScript for %s, got %v", tc.name, reflections)
				}
				if !tc.expectScript && r.Context == ContextScript {
					t.Fatalf("expected non-script context for %s, got %v", tc.name, reflections)
				}
				break
			}
			if !found {
				t.Fatalf("expected reflection in %s for %s, got %v", tc.attrName, tc.name, reflections)
			}
		})
	}
}

func TestDetectReflections_JSONScriptBlock(t *testing.T) {
	body := `<html><body><script type="application/json">nucleiXSScanary</script></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in non-executable script block")
	}
	if reflections[0].Context != ContextHTMLText {
		t.Fatalf("expected ContextHTMLText for application/json script block, got %s", reflections[0].Context)
	}
}

func TestDetectReflections_SrcdocAttribute(t *testing.T) {
	body := `<html><body><iframe srcdoc="nucleiXSScanary"></iframe></body></html>`
	reflections := DetectReflections(body, testMarker)
	if len(reflections) == 0 {
		t.Fatal("expected at least one reflection in srcdoc attribute")
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
	body := `<html><body><p>NUCLEIXSSCANARY</p></body></html>`
	reflections := DetectReflections(body, testMarker)
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

func TestSelectPayloads_ScriptStringIncludesTemplateLiteral(t *testing.T) {
	payloads := selectPayloads(&ReflectionInfo{Context: ContextScriptString}, CharacterSet{})
	found := false
	for _, payload := range payloads {
		if payload == "${alert(1)}" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected template literal payload in script string candidates, got %v", payloads)
	}
}

func TestIsExecutableScriptType_ParameterizedTypes(t *testing.T) {
	tests := []struct {
		name       string
		hasType    bool
		scriptType string
		expected   bool
	}{
		{name: "missing type attribute", hasType: false, scriptType: "", expected: true},
		{name: "empty type attribute", hasType: true, scriptType: "", expected: true},
		{name: "parameterized javascript type", hasType: true, scriptType: "text/javascript; charset=utf-8", expected: true},
		{name: "parameterized non-js type", hasType: true, scriptType: "application/json; charset=utf-8", expected: false},
		{name: "parameter only", hasType: true, scriptType: ";charset=utf-8", expected: false},
		{name: "json script type", hasType: true, scriptType: "application/json", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExecutableScriptType(tt.hasType, tt.scriptType); got != tt.expected {
				t.Fatalf("isExecutableScriptType(%v, %q) = %v, want %v", tt.hasType, tt.scriptType, got, tt.expected)
			}
		})
	}
}

func TestIsExecutableScriptType_LegacyMIMETypes(t *testing.T) {
	legacyTypes := []string{
		"text/javascript",
		"text/ecmascript",
		"text/javascript1.0",
		"text/javascript1.1",
		"text/javascript1.2",
		"text/javascript1.3",
		"text/javascript1.4",
		"text/javascript1.5",
		"text/jscript",
		"text/livescript",
		"text/x-ecmascript",
		"text/x-javascript",
		"application/javascript",
		"application/ecmascript",
		"application/x-ecmascript",
		"application/x-javascript",
		"module",
	}

	for _, mimeType := range legacyTypes {
		t.Run(mimeType, func(t *testing.T) {
			if !isExecutableScriptType(true, mimeType) {
				t.Fatalf("expected MIME type %q to be executable", mimeType)
			}
		})
	}
}

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
	body := canary + `&lt;` + canary + `&gt;` + canary + `&quot;` + canary + `&#39;` + canary + "/"
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

func TestDetectReflections_EncodedSchemesAndXHTMLDataURI(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		attrName string
	}{
		{
			name:     "percent encoded javascript scheme",
			body:     `<html><body><a href="%6A%61%76%61%73%63%72%69%70%74:alert(1)#nucleiXSScanary">test</a></body></html>`,
			attrName: "href",
		},
		{
			name:     "percent encoded data html in iframe src",
			body:     `<html><body><iframe src="%64%61%74%61:text/html,<script>alert(1)</script>#nucleiXSScanary"></iframe></body></html>`,
			attrName: "src",
		},
		{
			name:     "data xhtml in iframe src",
			body:     `<html><body><iframe src="data:application/xhtml+xml,<html xmlns='http://www.w3.org/1999/xhtml'><script>alert(1)</script></html>#nucleiXSScanary"></iframe></body></html>`,
			attrName: "src",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reflections := DetectReflections(tc.body, testMarker)
			if len(reflections) == 0 {
				t.Fatalf("expected at least one reflection for %s", tc.name)
			}

			found := false
			for _, r := range reflections {
				if r.AttrName == tc.attrName && r.Context == ContextScript {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected ContextScript in %s for %s, got %v", tc.attrName, tc.name, reflections)
			}
		})
	}
}
