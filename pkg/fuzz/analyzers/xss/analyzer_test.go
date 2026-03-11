package xss

import (
	"strings"
	"testing"
)

// ---- helpers ----

func assertContext(t *testing.T, name, body, marker string, want XSSContext) {
	t.Helper()
	result := AnalyzeReflectionContext(body, marker)
	if result.Context != want {
		t.Errorf("[%s] AnalyzeReflectionContext(%q, %q)\n  got  context=%s\n  want context=%s",
			name, body, marker, result.Context, want)
	}
}

func assertNotEmpty(t *testing.T, name string, result XSSResult) {
	t.Helper()
	if len(result.Payloads) == 0 {
		t.Errorf("[%s] expected payloads but got none", name)
	}
	if result.Explanation == "" {
		t.Errorf("[%s] expected non-empty explanation", name)
	}
}

// ---- TestAnalyzeReflectionContext_HTMLBody ----

func TestAnalyzeReflectionContext_HTMLBody(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "bare text between p tags",
			body:   `<html><body><p>MARKER</p></body></html>`,
			marker: "MARKER",
			want:   ContextHTMLBody,
		},
		{
			name:   "text in div",
			body:   `<div>Hello MARKER world</div>`,
			marker: "MARKER",
			want:   ContextHTMLBody,
		},
		{
			name:   "text at root level",
			body:   `<html>MARKER</html>`,
			marker: "MARKER",
			want:   ContextHTMLBody,
		},
		{
			name:   "case-insensitive marker",
			body:   `<div>hello marker world</div>`,
			marker: "MARKER",
			want:   ContextHTMLBody,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_HTMLComment ----

func TestAnalyzeReflectionContext_HTMLComment(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "marker in html comment",
			body:   `<!-- MARKER -->`,
			marker: "MARKER",
			want:   ContextComment,
		},
		{
			name:   "marker in nested comment",
			body:   `<html><!-- version: MARKER --><body></body></html>`,
			marker: "MARKER",
			want:   ContextComment,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_AttributeDoubleQuote ----

func TestAnalyzeReflectionContext_AttributeDoubleQuote(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "value in double-quoted attr",
			body:   `<input value="MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeDouble,
		},
		{
			name:   "value in double-quoted class",
			body:   `<div class="container MARKER active">`,
			marker: "MARKER",
			want:   ContextAttributeDouble,
		},
		{
			name:   "value in double-quoted data attr",
			body:   `<div data-x="MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeDouble,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_AttributeSingleQuote ----

func TestAnalyzeReflectionContext_AttributeSingleQuote(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "value in single-quoted attr",
			body:   `<input value='MARKER'>`,
			marker: "MARKER",
			want:   ContextAttributeSingle,
		},
		{
			name:   "value in single-quoted class",
			body:   `<div class='header MARKER'>`,
			marker: "MARKER",
			want:   ContextAttributeSingle,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_URLAttribute ----

func TestAnalyzeReflectionContext_URLAttribute(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "marker in href",
			body:   `<a href="/path/MARKER">click</a>`,
			marker: "MARKER",
			want:   ContextAttributeURL,
		},
		{
			name:   "marker in img src",
			body:   `<img src="https://example.com/MARKER.png">`,
			marker: "MARKER",
			want:   ContextAttributeURL,
		},
		{
			name:   "marker in form action",
			body:   `<form action="/submit/MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeURL,
		},
		{
			name:   "marker in iframe src",
			body:   `<iframe src="MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeURL,
		},
		{
			name:   "javascript: in a href — executable sink",
			body:   `<a href="javascript:MARKER">click</a>`,
			marker: "MARKER",
			want:   ContextScript,
		},
		{
			name:   "javascript: in img src — NOT executable",
			body:   `<img src="javascript:MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeURL,
		},
		{
			name:   "javascript: in area href",
			body:   `<area href="javascript:MARKER">`,
			marker: "MARKER",
			want:   ContextScript,
		},
		{
			name:   "javascript: in iframe src — executable",
			body:   `<iframe src="javascript:MARKER"></iframe>`,
			marker: "MARKER",
			want:   ContextScript,
		},
		{
			name:   "data:text/html in a href",
			body:   `<a href="data:text/html,MARKER">link</a>`,
			marker: "MARKER",
			want:   ContextScript,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_EventHandler ----

func TestAnalyzeReflectionContext_EventHandler(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "marker in onclick",
			body:   `<button onclick="doSomething(MARKER)">click</button>`,
			marker: "MARKER",
			want:   ContextAttributeEvent,
		},
		{
			name:   "marker in onerror",
			body:   `<img src=x onerror="MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeEvent,
		},
		{
			name:   "marker in onload",
			body:   `<body onload="MARKER">`,
			marker: "MARKER",
			want:   ContextAttributeEvent,
		},
		{
			name:   "marker in onfocus",
			body:   `<input onfocus="alert(MARKER)" autofocus>`,
			marker: "MARKER",
			want:   ContextAttributeEvent,
		},
		{
			name:   "marker in ontoggle",
			body:   `<details ontoggle="MARKER" open>`,
			marker: "MARKER",
			want:   ContextAttributeEvent,
		},
		{
			name:   "marker in onmouseover",
			body:   `<div onmouseover="log(MARKER)">hover me</div>`,
			marker: "MARKER",
			want:   ContextAttributeEvent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_ScriptBlock ----

func TestAnalyzeReflectionContext_ScriptBlock(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "marker in script block (no type)",
			body:   `<script>var x = "MARKER";</script>`,
			marker: "MARKER",
			want:   ContextScript,
		},
		{
			name:   "marker in script type=text/javascript",
			body:   `<script type="text/javascript">var x = MARKER;</script>`,
			marker: "MARKER",
			want:   ContextScript,
		},
		{
			name:   "marker in script type=module",
			body:   `<script type="module">import {MARKER} from './mod.js';</script>`,
			marker: "MARKER",
			want:   ContextScript,
		},
		{
			name:   "non-executable script type (JSON)",
			body:   `<script type="application/json">{"key": "MARKER"}</script>`,
			marker: "MARKER",
			want:   ContextScriptData,
		},
		{
			name:   "non-executable script type (ld+json)",
			body:   `<script type="application/ld+json">{"@type": "MARKER"}</script>`,
			marker: "MARKER",
			want:   ContextScriptData,
		},
		{
			name:   "first type attr wins (first=non-exec, second=exec)",
			body:   `<script type="application/json" type="text/javascript">MARKER</script>`,
			marker: "MARKER",
			want:   ContextScriptData,
		},
		{
			name:   "marker in template literal",
			body:   `<script>var s = ` + "`" + `hello ${MARKER} world` + "`" + `;</script>`,
			marker: "MARKER",
			want:   ContextTemplate,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_StyleBlock ----

func TestAnalyzeReflectionContext_StyleBlock(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
		want   XSSContext
	}{
		{
			name:   "marker in style block",
			body:   `<style>body { color: MARKER; }</style>`,
			marker: "MARKER",
			want:   ContextStyle,
		},
		{
			name:   "marker in style block url",
			body:   `<style>body { background: url("MARKER"); }</style>`,
			marker: "MARKER",
			want:   ContextStyle,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertContext(t, tc.name, tc.body, tc.marker, tc.want)
		})
	}
}

// ---- TestAnalyzeReflectionContext_InlineStyle ----

func TestAnalyzeReflectionContext_InlineStyle(t *testing.T) {
	assertContext(t, "inline style attr",
		`<div style="color: MARKER;">text</div>`,
		"MARKER",
		ContextAttributeStyle,
	)
}

// ---- TestAnalyzeReflectionContext_SrcDoc ----

func TestAnalyzeReflectionContext_SrcDoc(t *testing.T) {
	assertContext(t, "srcdoc attribute",
		`<iframe srcdoc="<p>MARKER</p>"></iframe>`,
		"MARKER",
		ContextSrcDoc,
	)
}

// ---- TestAnalyzeReflectionContext_NotFound ----

func TestAnalyzeReflectionContext_NotFound(t *testing.T) {
	result := AnalyzeReflectionContext(`<html><body><p>hello</p></body></html>`, "MARKER")
	if result.Context != ContextUnknown {
		t.Errorf("expected ContextUnknown for missing marker, got %s", result.Context)
	}
}

// ---- TestAnalyzeReflectionContext_EmptyInputs ----

func TestAnalyzeReflectionContext_EmptyInputs(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		marker string
	}{
		{"empty body", "", "MARKER"},
		{"empty marker", "<html>MARKER</html>", ""},
		{"both empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := AnalyzeReflectionContext(tc.body, tc.marker)
			if result.Context != ContextUnknown {
				t.Errorf("[%s] expected ContextUnknown, got %s", tc.name, result.Context)
			}
		})
	}
}

// ---- TestAnalyzeAllReflections_MultipleContexts ----

func TestAnalyzeAllReflections_MultipleContexts(t *testing.T) {
	// marker reflected in two different places
	body := `<div>MARKER</div><script>var x = "MARKER"</script>`
	results := AnalyzeAllReflections(body, "MARKER")
	if len(results) < 2 {
		t.Errorf("expected at least 2 reflections, got %d", len(results))
		return
	}
	ctxs := make(map[XSSContext]bool)
	for _, r := range results {
		ctxs[r.Context] = true
	}
	if !ctxs[ContextHTMLBody] {
		t.Error("expected ContextHTMLBody in results")
	}
	if !ctxs[ContextScript] {
		t.Error("expected ContextScript in results")
	}
}

// ---- TestAnalyzeReflectionContext_BestContextSelected ----

// When reflected in multiple places, AnalyzeReflectionContext returns the most
// exploitable context (script > attr > body).
func TestAnalyzeReflectionContext_BestContextSelected(t *testing.T) {
	body := `<div>MARKER</div><script>var x = "MARKER"</script>`
	result := AnalyzeReflectionContext(body, "MARKER")
	if result.Context != ContextScript {
		t.Errorf("expected ContextScript (highest priority), got %s", result.Context)
	}
}

// ---- TestPayloads_NonEmpty ----

func TestPayloads_NonEmpty(t *testing.T) {
	// Verify every context has non-empty payloads
	testCases := []struct {
		name string
		body string
	}{
		{"HTMLBody", `<p>MARKER</p>`},
		{"Comment", `<!-- MARKER -->`},
		{"AttributeDouble", `<div class="MARKER">`},
		{"AttributeSingle", `<div class='MARKER'>`},
		{"AttributeURL", `<a href="MARKER">x</a>`},
		{"EventHandler", `<div onclick="MARKER">`},
		{"InlineStyle", `<div style="MARKER">`},
		{"ScriptExec", `<script>MARKER</script>`},
		{"ScriptData", `<script type="application/json">MARKER</script>`},
		{"StyleBlock", `<style>MARKER</style>`},
		{"SrcDoc", `<iframe srcdoc="MARKER">`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := AnalyzeReflectionContext(tc.body, "MARKER")
			assertNotEmpty(t, tc.name, result)
			if result.Confidence <= 0 {
				t.Errorf("[%s] expected confidence > 0, got %f", tc.name, result.Confidence)
			}
		})
	}
}

// ---- TestContextString ----

func TestContextString(t *testing.T) {
	known := []XSSContext{
		ContextUnknown, ContextHTMLBody, ContextComment,
		ContextAttributeDouble, ContextAttributeSingle, ContextAttributeUnquoted,
		ContextAttributeURL, ContextAttributeEvent, ContextAttributeStyle,
		ContextScript, ContextScriptData, ContextStyle,
		ContextJSON, ContextTemplate, ContextCDATA, ContextSrcDoc,
	}
	for _, ctx := range known {
		s := ctx.String()
		if s == "" || strings.HasPrefix(s, "XSSContext(") {
			t.Errorf("context %d has no name (got %q)", int(ctx), s)
		}
	}
}

// ---- TestIsScriptTypeExecutable ----

func TestIsScriptTypeExecutable(t *testing.T) {
	execTypes := []string{
		"", "text/javascript", "application/javascript",
		"module", "text/ecmascript", "text/javascript; charset=utf-8",
	}
	for _, typ := range execTypes {
		if !isScriptTypeExecutable(typ) {
			t.Errorf("expected type %q to be executable", typ)
		}
	}

	nonExecTypes := []string{
		"application/json", "application/ld+json", "text/plain",
		"text/html", "text/template",
	}
	for _, typ := range nonExecTypes {
		if isScriptTypeExecutable(typ) {
			t.Errorf("expected type %q to NOT be executable", typ)
		}
	}
}

// ---- TestIsInTemplateLiteral ----

func TestIsInTemplateLiteral(t *testing.T) {
	if !isInTemplateLiteral("`hello ${marker} world`", "marker") {
		t.Error("expected template literal detection")
	}
	if isInTemplateLiteral(`var x = "marker"`, "marker") {
		t.Error("should not detect template literal in double-quoted string")
	}
	if !isInTemplateLiteral("`prefix` + `${marker}`", "marker") {
		t.Error("expected detection in second template literal")
	}
}

// ---- TestEventHandlerPayloads ----

func TestEventHandlerPayloads_AreDirectJS(t *testing.T) {
	result := AnalyzeReflectionContext(`<button onclick="MARKER">x</button>`, "MARKER")
	if result.Context != ContextAttributeEvent {
		t.Fatalf("expected ContextAttributeEvent, got %s", result.Context)
	}
	if !result.IsExecutableSink {
		t.Error("event handler should be an executable sink")
	}
	// Payloads for event handler should not include <script> tags (unnecessary)
	for _, p := range result.Payloads {
		if strings.Contains(p, "<script>") {
			t.Logf("note: payload contains <script>, fine but unnecessary for event handler: %q", p)
		}
	}
}

// ---- TestJavaScriptURIMisclassification_Issue7086 ----
//
// Issue #7086: javascript: URIs were being misclassified.
// Specifically, javascript: in <img src=""> should NOT be ContextScript
// because img doesn't execute javascript: URIs.

func TestJavaScriptURIMisclassification_Issue7086(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		marker    string
		wantCtx   XSSContext
		wantExec  bool
	}{
		{
			name:     "<img src=javascript:> is NOT executable",
			body:     `<img src="javascript:MARKER">`,
			marker:   "MARKER",
			wantCtx:  ContextAttributeURL,
			wantExec: false,
		},
		{
			name:     "<a href=javascript:> IS executable",
			body:     `<a href="javascript:MARKER">x</a>`,
			marker:   "MARKER",
			wantCtx:  ContextScript,
			wantExec: true,
		},
		{
			name:     "<script src=javascript:> src is not inline exec",
			body:     `<script src="javascript:MARKER"></script>`,
			marker:   "MARKER",
			wantCtx:  ContextAttributeURL,
			wantExec: false,
		},
		{
			name:     "<iframe src=javascript:> IS executable",
			body:     `<iframe src="javascript:MARKER"></iframe>`,
			marker:   "MARKER",
			wantCtx:  ContextScript,
			wantExec: true,
		},
		{
			name:     "<form action=javascript:> IS executable",
			body:     `<form action="javascript:MARKER">`,
			marker:   "MARKER",
			wantCtx:  ContextScript,
			wantExec: true,
		},
		{
			name:     "vbscript: in a href is executable",
			body:     `<a href="vbscript:MARKER">x</a>`,
			marker:   "MARKER",
			wantCtx:  ContextScript,
			wantExec: true,
		},
		{
			name:     "data:text/html in object data IS executable",
			body:     `<object data="data:text/html,MARKER">`,
			marker:   "MARKER",
			wantCtx:  ContextScript,
			wantExec: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := AnalyzeReflectionContext(tc.body, tc.marker)
			if result.Context != tc.wantCtx {
				t.Errorf("context: got %s, want %s", result.Context, tc.wantCtx)
			}
			if result.IsExecutableSink != tc.wantExec {
				t.Errorf("IsExecutableSink: got %v, want %v", result.IsExecutableSink, tc.wantExec)
			}
		})
	}
}

// ---- TestFirstTypeAttrWins ----

// Per HTML5 spec, when a <script> has duplicate type attrs, the first one wins.
func TestFirstTypeAttrWins(t *testing.T) {
	// First type=application/json → non-executable; second type=text/javascript is ignored
	body := `<script type="application/json" type="text/javascript">MARKER</script>`
	assertContext(t, "first type wins", body, "MARKER", ContextScriptData)
}

// ---- TestCaseSensitivity ----

func TestCaseSensitivity(t *testing.T) {
	// Event handler attr names in uppercase
	assertContext(t, "uppercase ONCLICK",
		`<div ONCLICK="MARKER">`, "MARKER", ContextAttributeEvent)

	// Marker in mixed case
	assertContext(t, "mixed case marker",
		`<script>var x = "MaRkEr";</script>`, "marker", ContextScript)
}

// ---- TestNestedQuotes ----

func TestNestedQuotes(t *testing.T) {
	// Double-quoted attr containing single quotes around marker
	assertContext(t, "nested single quotes in double-quoted attr",
		`<input value="it's 'MARKER' here">`, "MARKER", ContextAttributeDouble)

	// Single-quoted attr containing double quotes
	assertContext(t, "nested double quotes in single-quoted attr",
		`<input value='say "MARKER"'>`, "MARKER", ContextAttributeSingle)
}

// ---- TestAnalyzeAllReflections_Returns ----

func TestAnalyzeAllReflections_NoMatch(t *testing.T) {
	results := AnalyzeAllReflections("<html><body>hello</body></html>", "MARKER")
	if len(results) != 0 {
		t.Errorf("expected 0 results for no match, got %d", len(results))
	}
}

// ---- TestContextPriority ----

func TestContextPriority(t *testing.T) {
	// Script should beat HTMLBody
	if contextPriority(ContextScript) >= contextPriority(ContextHTMLBody) {
		t.Error("ContextScript should have higher priority (lower number) than ContextHTMLBody")
	}
	// Event handler should beat generic attribute
	if contextPriority(ContextAttributeEvent) >= contextPriority(ContextAttributeDouble) {
		t.Error("ContextAttributeEvent should have higher priority than ContextAttributeDouble")
	}
}

// ---- Benchmarks ----

func BenchmarkAnalyzeReflectionContext_HTMLBody(b *testing.B) {
	body := `<html><head><title>Test</title></head><body><div class="container"><p>Hello MARKER world</p></div></body></html>`
	for i := 0; i < b.N; i++ {
		AnalyzeReflectionContext(body, "MARKER")
	}
}

func BenchmarkAnalyzeReflectionContext_LargeDocument(b *testing.B) {
	// simulate a realistic HTML page
	body := strings.Repeat(`<div class="item"><p>Lorem ipsum dolor sit amet</p><a href="/page">link</a></div>`, 200) +
		`<script>var data = {user: "MARKER", token: "abc123"};</script>` +
		strings.Repeat(`<div class="footer">more content here</div>`, 50)
	for i := 0; i < b.N; i++ {
		AnalyzeReflectionContext(body, "MARKER")
	}
}

func BenchmarkAnalyzeAllReflections(b *testing.B) {
	body := `<p>MARKER</p><script>var x="MARKER";</script><!-- MARKER --><div onclick="MARKER">`
	for i := 0; i < b.N; i++ {
		AnalyzeAllReflections(body, "MARKER")
	}
}
