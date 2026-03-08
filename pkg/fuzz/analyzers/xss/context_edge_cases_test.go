package xss

import (
	"testing"
)

// TestJavascriptURIClassifiedAsScript verifies Fix #1:
// <a href="javascript:..."> must be ContextScript, not ContextAttribute.
func TestJavascriptURIClassifiedAsScript(t *testing.T) {
	marker := "nucleiXSScanary"
	body := `<a href="javascript:alert(nucleiXSScanary)">click</a>`

	reflections := DetectReflections(body, marker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection, got none")
	}
	best := BestReflection(reflections)
	if best.Context != ContextScript {
		t.Errorf("javascript: URI: got context %v, want %v", best.Context, ContextScript)
	}
}

// TestJavascriptURISingleQuoted verifies Fix #1 with single-quoted attributes.
func TestJavascriptURISingleQuoted(t *testing.T) {
	marker := "nucleiXSScanary"
	body := `<a href='javascript:nucleiXSScanary()'>click</a>`

	reflections := DetectReflections(body, marker)
	best := BestReflection(reflections)
	if best == nil || best.Context != ContextScript {
		got := "nil"
		if best != nil {
			got = best.Context.String()
		}
		t.Errorf("javascript: URI (single quote): got %v, want script", got)
	}
}

// TestNonExecutableScriptBlock verifies that <script type="application/json">
// is classified as ContextScript (not ContextHTMLText).
//
// Rationale: the HTML parser treats ALL <script> blocks as raw text regardless
// of the type attribute. A </script> injection therefore still breaks out and
// is a live XSS sink. selectPayloads() needs ContextScript to emit that path.
// The distinction between "executable JS" and "data block" is handled at the
// payload-selection layer, not at the context-detection layer.
func TestNonExecutableScriptBlock(t *testing.T) {
	marker := "nucleiXSScanary"
	body := `<script type="application/json">{"key": "nucleiXSScanary"}</script>`

	reflections := DetectReflections(body, marker)
	if len(reflections) == 0 {
		t.Fatal("expected reflection inside application/json block, got none")
	}
	best := BestReflection(reflections)
	if best.Context != ContextScript {
		t.Errorf("application/json script block: got context %v, want ContextScript (raw-text breakout)", best.Context)
	}
}

// TestNonExecutableScriptVariants verifies that non-executable script types
// still yield ContextScript (raw-text breakout path, not ContextHTMLText).
func TestNonExecutableScriptVariants(t *testing.T) {
	marker := "nucleiXSScanary"
	cases := []struct {
		name     string
		mimeType string
	}{
		{"ld+json", "application/ld+json"},
		{"text/template", "text/template"},
		{"text/plain", "text/plain"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `<script type="` + tc.mimeType + `">nucleiXSScanary</script>`
			reflections := DetectReflections(body, marker)
			if len(reflections) == 0 {
				t.Fatalf("type %q: expected reflection, got none", tc.mimeType)
			}
			best := BestReflection(reflections)
			if best.Context != ContextScript {
				t.Errorf("type %q: got %v, want ContextScript (raw-text breakout)", tc.mimeType, best.Context)
			}
		})
	}
}

// TestExecutableScriptWithoutType verifies Fix #2 does not break the normal case:
// <script> without type attribute must still be ContextScript.
func TestExecutableScriptWithoutType(t *testing.T) {
	marker := "nucleiXSScanary"
	body := `<script>var x = "nucleiXSScanary";</script>`

	reflections := DetectReflections(body, marker)
	best := BestReflection(reflections)
	if best == nil || (best.Context != ContextScript && best.Context != ContextScriptString) {
		got := "nil"
		if best != nil {
			got = best.Context.String()
		}
		t.Errorf("<script> without type: got %v, want script/script_string", got)
	}
}

// TestCaseInsensitiveReflectionDetection verifies Fix #3:
// Reflections of a transformed (uppercased) marker should be detected.
func TestCaseInsensitiveReflectionDetection(t *testing.T) {
	marker := "nucleiXSScanary"
	// Server uppercased the value
	body := `<div>NUCLEIXSSCANARY</div>`

	reflections := DetectReflections(body, marker)
	if len(reflections) == 0 {
		t.Error("case-insensitive detection: expected reflection for uppercased marker, got none")
	}
}

// TestSrcdocClassifiedAsHTMLText verifies Fix #4:
// srcdoc attribute must be ContextHTMLText, not ContextAttribute.
func TestSrcdocClassifiedAsHTMLText(t *testing.T) {
	marker := "nucleiXSScanary"
	body := `<iframe srcdoc="<b>nucleiXSScanary</b>"></iframe>`

	reflections := DetectReflections(body, marker)
	if len(reflections) == 0 {
		t.Fatal("srcdoc: expected reflection, got none")
	}
	best := BestReflection(reflections)
	if best.Context != ContextHTMLText {
		t.Errorf("srcdoc: got context %v, want %v", best.Context, ContextHTMLText)
	}
}

// TestEventHandlerStillWorksAsScript ensures Fix #1 doesn't break event handler detection.
func TestEventHandlerStillWorksAsScript(t *testing.T) {
	marker := "nucleiXSScanary"
	body := `<img onerror="nucleiXSScanary()">`

	reflections := DetectReflections(body, marker)
	best := BestReflection(reflections)
	if best == nil || best.Context != ContextScript {
		got := "nil"
		if best != nil {
			got = best.Context.String()
		}
		t.Errorf("event handler: got %v, want script", got)
	}
}

// TestJavascriptURIWithLeadingWhitespace: browsers strip leading whitespace.
func TestJavascriptURIWithLeadingWhitespace(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"plain", "javascript:alert(1)", true},
		{"tab prefix", "\tjavascript:alert(1)", true},
		{"spaces prefix", "  javascript:alert(1)", true},
		{"newline prefix", "\njavascript:alert(1)", true},
		{"uppercase", "  JAVASCRIPT:alert(1)", true},
		{"https not js", "https://example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isJavascriptURI(tc.input)
			if got != tc.want {
				t.Errorf("isJavascriptURI(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestDataHTMLURIDetection: data:text/html URIs must be flagged as script context.
func TestDataHTMLURIDetection(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"data text/html", "data:text/html,<script>alert(1)</script>", true},
		{"data text/html base64", "data:text/html;base64,PHNjcmlwdD4=", true},
		{"data image/png", "data:image/png;base64,abc", false},
		{"data text/plain", "data:text/plain,hello", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isDataHTMLURI(tc.input)
			if got != tc.want {
				t.Errorf("isDataHTMLURI(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestIsExecutableScriptTagWordBoundary: "data-type=" must NOT suppress executable detection.
func TestIsExecutableScriptTagWordBoundary(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"no type attr", `<script>`, true},
		{"type=text/javascript", `<script type="text/javascript">`, true},
		{"type=application/json", `<script type="application/json">`, false},
		{"type with spaces around =", `<script type = "application/json">`, false},
		{"data-type should not match", `<script data-type="application/json">`, true},
		{"type=text/template", `<script type='text/template'>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isExecutableScriptTag(tc.token)
			if got != tc.want {
				t.Errorf("isExecutableScriptTag(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// TestIsExecutableScriptTagWhitelist verifies that ONLY known JavaScript MIME types
// are treated as executable. Unknown types must NOT be flagged as ContextScript.
// (WHATWG spec: unknown type → data block, not executable)
func TestIsExecutableScriptTagWhitelist(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		// Executable — known JS MIME types
		{"text/javascript", `<script type="text/javascript">`, true},
		{"application/javascript", `<script type="application/javascript">`, true},
		{"text/ecmascript", `<script type="text/ecmascript">`, true},
		{"application/ecmascript", `<script type="application/ecmascript">`, true},
		{"text/x-javascript", `<script type="text/x-javascript">`, true},
		{"application/x-javascript", `<script type="application/x-javascript">`, true},
		{"module", `<script type="module">`, true},
		{"no type", `<script>`, true},
		// Non-executable — unknown / data / template types
		{"application/x-custom", `<script type="application/x-custom">`, false},
		{"text/x-handlebars", `<script type="text/x-handlebars-template">`, false},
		{"text/plain", `<script type="text/plain">`, false},
		{"image/svg+xml", `<script type="image/svg+xml">`, false},
		{"application/wasm", `<script type="application/wasm">`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isExecutableScriptTag(tc.token)
			if got != tc.want {
				t.Errorf("isExecutableScriptTag(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// TestDataURIExactMediaTypeParsing verifies that isDataHTMLURI() performs exact
// media-type matching and does not false-positive on invalid types like
// data:text/htmlfoo or data:text/javascriptx (CodeRabbit 2026-03-07).
func TestDataURIExactMediaTypeParsing(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// Exact matches — executable
		{"data:text/html,<script>alert(1)</script>", true},
		{"data:text/html;charset=utf-8,<b>x</b>", true},
		{"data:text/javascript,alert(1)", true},
		{"data:text/javascript;base64,YWxlcnQoMSk=", true},
		{"data:application/javascript,alert(1)", true},
		{"data:image/svg+xml,<svg/>", true},
		{"data:image/svg+xml;charset=utf-8,<svg/>", true},
		// Invalid / partial MIME types — must NOT match
		{"data:text/htmlfoo,payload", false},
		{"data:text/javascriptx,payload", false},
		{"data:application/javascriptextra,payload", false},
		{"data:image/svg+xmlplus,payload", false},
		// Safe MIME types
		{"data:image/png;base64,abc", false},
		{"data:text/plain,hello", false},
		{"data:audio/mpeg;base64,abc", false},
	}
	for _, tc := range cases {
		got := isDataHTMLURI(tc.input)
		if got != tc.want {
			t.Errorf("isDataHTMLURI(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// TestDataURIExecutableMIMETypes verifies that data: URIs with executable MIME types
// are classified as ContextScript (Neo bot issue: incomplete data: URI coverage).
func TestDataURIExecutableMIMETypes(t *testing.T) {
	marker := "nucleiXSScanary"

	executableURIs := []struct {
		name string
		uri  string
	}{
		{"data:text/html", "data:text/html,<b>nucleiXSScanary</b>"},
		{"data:text/javascript", "data:text/javascript,nucleiXSScanary()"},
		{"data:application/javascript", "data:application/javascript,nucleiXSScanary()"},
		{"data:image/svg+xml", "data:image/svg+xml,<svg><script>nucleiXSScanary()</script></svg>"},
	}
	for _, tc := range executableURIs {
		t.Run(tc.name, func(t *testing.T) {
			body := `<a href="` + tc.uri + `">click</a>`
			reflections := DetectReflections(body, marker)
			best := BestReflection(reflections)
			if best == nil || best.Context != ContextScript {
				got := "nil"
				if best != nil {
					got = best.Context.String()
				}
				t.Errorf("data URI %q: got context %v, want ContextScript", tc.uri, got)
			}
		})
	}

	// Verify safe data: URIs are NOT flagged as executable
	safeURIs := []struct {
		name string
		uri  string
	}{
		{"data:image/png", "data:image/png;base64,nucleiXSScanary"},
		{"data:text/plain", "data:text/plain,nucleiXSScanary"},
		{"data:audio/mpeg", "data:audio/mpeg;base64,nucleiXSScanary"},
	}
	for _, tc := range safeURIs {
		t.Run("safe_"+tc.name, func(t *testing.T) {
			got := isDataHTMLURI(tc.uri)
			if got {
				t.Errorf("safe data URI %q should NOT be flagged as executable", tc.uri)
			}
		})
	}
}
