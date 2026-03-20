package xss

import "testing"

func TestAnalyzeReflectionContext(t *testing.T) {
	const marker = "FUZZ1337MARKER"

	tests := []struct {
		name     string
		body     string
		marker   string
		expected XSSContext
	}{
		// === HTML Body Context ===
		{
			name:     "reflection in plain HTML body text",
			body:     `<html><body><p>Hello FUZZ1337MARKER world</p></body></html>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "reflection in nested div body text",
			body:     `<div><span>text FUZZ1337MARKER more</span></div>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},

		// === Generic Attribute Context ===
		{
			name:     "reflection in regular attribute value",
			body:     `<input type="text" value="FUZZ1337MARKER">`,
			marker:   marker,
			expected: ContextHTMLAttribute,
		},
		{
			name:     "reflection in class attribute",
			body:     `<div class="foo FUZZ1337MARKER bar">text</div>`,
			marker:   marker,
			expected: ContextHTMLAttribute,
		},
		{
			name:     "reflection in data-custom attribute",
			body:     `<div data-info="FUZZ1337MARKER">text</div>`,
			marker:   marker,
			expected: ContextHTMLAttribute,
		},
		{
			name:     "reflection in title attribute",
			body:     `<img title="FUZZ1337MARKER">`,
			marker:   marker,
			expected: ContextHTMLAttribute,
		},

		// === URL Attribute Context ===
		{
			name:     "reflection in href with regular URL",
			body:     `<a href="https://example.com/FUZZ1337MARKER">link</a>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "reflection in src attribute",
			body:     `<img src="/images/FUZZ1337MARKER.png">`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "reflection in action attribute",
			body:     `<form action="/submit/FUZZ1337MARKER"></form>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "reflection in formaction attribute",
			body:     `<button formaction="/do/FUZZ1337MARKER">Go</button>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},

		{
			name:     "reflection in longdesc attribute",
			body:     `<img longdesc="https://example.com/desc/FUZZ1337MARKER">`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},

		// === Event Handler Attribute Context ===
		{
			name:     "reflection in onclick handler",
			body:     `<button onclick="doSomething('FUZZ1337MARKER')">Click</button>`,
			marker:   marker,
			expected: ContextHTMLAttributeEvent,
		},
		{
			name:     "reflection in onmouseover handler",
			body:     `<div onmouseover="alert('FUZZ1337MARKER')">hover</div>`,
			marker:   marker,
			expected: ContextHTMLAttributeEvent,
		},
		{
			name:     "reflection in onerror handler",
			body:     `<img src="x" onerror="log('FUZZ1337MARKER')">`,
			marker:   marker,
			expected: ContextHTMLAttributeEvent,
		},
		{
			name:     "reflection in onload handler",
			body:     `<body onload="init('FUZZ1337MARKER')">`,
			marker:   marker,
			expected: ContextHTMLAttributeEvent,
		},
		{
			name:     "reflection in onauxclick handler",
			body:     `<div onauxclick="handle('FUZZ1337MARKER')">right-click</div>`,
			marker:   marker,
			expected: ContextHTMLAttributeEvent,
		},
		{
			name:     "reflection in onbeforeinput handler",
			body:     `<input onbeforeinput="check('FUZZ1337MARKER')">`,
			marker:   marker,
			expected: ContextHTMLAttributeEvent,
		},

		// === Script Context (executable) ===
		{
			name:     "reflection in script block with no type",
			body:     `<script>var x = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "reflection in script type=text/javascript",
			body:     `<script type="text/javascript">var x = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "reflection in script type=module",
			body:     `<script type="module">import "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "reflection in script type=application/javascript",
			body:     `<script type="application/javascript">var y = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "script type with MIME parameters still executable",
			body:     `<script type="text/javascript; charset=utf-8">var x = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},

		// === javascript: URI -> ContextScript ===
		{
			name:     "javascript URI in href must be ContextScript",
			body:     `<a href="javascript:alert('FUZZ1337MARKER')">xss</a>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "javascript URI with whitespace prefix",
			body:     `<a href="  javascript:void(FUZZ1337MARKER)">xss</a>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "javascript URI case-insensitive",
			body:     `<a href="JavaScript:alert('FUZZ1337MARKER')">xss</a>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "data:text/html URI in src",
			body:     `<iframe src="data:text/html,<h1>FUZZ1337MARKER</h1>">`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "data:application/xhtml+xml URI in src",
			body:     `<iframe src="data:application/xhtml+xml,<html xmlns='http://www.w3.org/1999/xhtml'><body>FUZZ1337MARKER</body></html>">`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "data:image/svg+xml URI in iframe src",
			body:     `<iframe src="data:image/svg+xml,<svg onload=alert(FUZZ1337MARKER)>">`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "data:image/svg+xml URI in img src does not execute",
			body:     `<img src="data:image/svg+xml,<svg>FUZZ1337MARKER</svg>">`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "vbscript URI in href",
			body:     `<a href="vbscript:msgbox(FUZZ1337MARKER)">click</a>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "javascript URI in img src does not execute",
			body:     `<img src="javascript:alert('FUZZ1337MARKER')">`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "javascript URI in ping does not execute",
			body:     `<a href="/" ping="javascript:FUZZ1337MARKER">click</a>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "reflection in ping attribute",
			body:     `<a href="/" ping="https://tracker.example.com/FUZZ1337MARKER">click</a>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},

		// === ScriptData Context (non-executable script) ===
		{
			name:     "reflection in script type=application/json",
			body:     `<script type="application/json">{"key": "FUZZ1337MARKER"}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},
		{
			name:     "reflection in script type=text/template",
			body:     `<script type="text/template"><div>FUZZ1337MARKER</div></script>`,
			marker:   marker,
			expected: ContextScriptData,
		},
		{
			name:     "reflection in script type=text/x-handlebars-template",
			body:     `<script type="text/x-handlebars-template">{{FUZZ1337MARKER}}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},
		{
			name:     "reflection in script type=application/ld+json",
			body:     `<script type="application/ld+json">{"name":"FUZZ1337MARKER"}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},

		{
			name:     "duplicate type attributes uses first per HTML5 spec",
			body:     `<script type="application/json" type="text/javascript">{"key": "FUZZ1337MARKER"}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},

		// === Style Context ===
		{
			name:     "reflection in style block",
			body:     `<style>.foo { color: FUZZ1337MARKER; }</style>`,
			marker:   marker,
			expected: ContextStyle,
		},
		{
			name:     "reflection in style attribute",
			body:     `<div style="color: FUZZ1337MARKER">text</div>`,
			marker:   marker,
			expected: ContextStyle,
		},

		// === Comment Context ===
		{
			name:     "reflection in HTML comment",
			body:     `<html><!-- FUZZ1337MARKER --><body></body></html>`,
			marker:   marker,
			expected: ContextComment,
		},
		{
			name:     "reflection in comment between tags",
			body:     `<div>text</div><!-- secret: FUZZ1337MARKER --><p>more</p>`,
			marker:   marker,
			expected: ContextComment,
		},

		// === srcdoc attribute -> HTMLBody ===
		{
			name:     "reflection in srcdoc attribute",
			body:     `<iframe srcdoc="<b>FUZZ1337MARKER</b>"></iframe>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},

		// === Case-insensitive matching ===
		{
			name:     "case-insensitive marker matching (lowercase body)",
			body:     `<p>fuzz1337marker appears here</p>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "case-insensitive marker matching (mixed case body)",
			body:     `<p>Fuzz1337Marker appears here</p>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "case-insensitive in attribute",
			body:     `<input value="fuzz1337marker">`,
			marker:   marker,
			expected: ContextHTMLAttribute,
		},

		// === Edge cases: marker not found ===
		{
			name:     "marker not found in response",
			body:     `<html><body><p>Hello world</p></body></html>`,
			marker:   marker,
			expected: ContextUnknown,
		},

		// === Edge cases: empty inputs ===
		{
			name:     "empty response body",
			body:     ``,
			marker:   marker,
			expected: ContextUnknown,
		},
		{
			name:     "empty marker",
			body:     `<p>Hello</p>`,
			marker:   "",
			expected: ContextUnknown,
		},

		// === Malformed HTML ===
		{
			name:     "malformed HTML with unclosed tags",
			body:     `<div><p>FUZZ1337MARKER<span>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "malformed HTML with no tags at all",
			body:     `just plain text FUZZ1337MARKER`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "malformed script tag not closed",
			body:     `<script>var x = "FUZZ1337MARKER";`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "broken HTML with unclosed attribute quote",
			body:     `<a href = "FUZZ1337MARKER >broken`,
			marker:   marker,
			expected: ContextUnknown, // tokenizer cannot parse unclosed quote reliably
		},
		{
			name:     "broken HTML with missing closing quote but valid parse",
			body:     `<a href=FUZZ1337MARKER>broken</a>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},

		// === Multiple reflections: first context wins ===
		{
			name:     "multiple reflections returns first context",
			body:     `<!-- FUZZ1337MARKER --><p>FUZZ1337MARKER</p>`,
			marker:   marker,
			expected: ContextComment,
		},

		// === Self-closing tags ===
		{
			name:     "reflection in self-closing tag attribute",
			body:     `<img src="FUZZ1337MARKER"/>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},

		// === Script tag attribute reflections ===
		{
			name:     "reflection in script src attribute",
			body:     `<script src="FUZZ1337MARKER"></script>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "reflection in script src with type attribute",
			body:     `<script type="text/javascript" src="FUZZ1337MARKER"></script>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},
		{
			name:     "script tag with src and type but reflection in text",
			body:     `<script type="text/javascript" src="app.js">var z = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "non-executable script with marker in src attribute",
			body:     `<script type="application/json" src="FUZZ1337MARKER"></script>`,
			marker:   marker,
			expected: ContextHTMLAttributeURL,
		},

		// === Noscript tag ===
		{
			name:     "reflection inside noscript",
			body:     `<noscript><p>FUZZ1337MARKER</p></noscript>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},

		// === Textarea ===
		{
			name:     "reflection inside textarea",
			body:     `<textarea>FUZZ1337MARKER</textarea>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},

		// ================================================================
		// Regression tests for issue #7086:
		// XSS Context Analyzer misclassifies javascript: URIs and JSON
		// script blocks.
		// ================================================================

		// --- #7086 Edge Case 1: javascript: URI classification ---
		// javascript: URIs in executable sinks must be ContextScript.
		{
			name:     "#7086: javascript: URI with tab in scheme (WHATWG normalization)",
			body:     "<a href=\"java\tscript:alert('FUZZ1337MARKER')\">xss</a>",
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: javascript: URI with newline in scheme",
			body:     "<a href=\"java\nscript:alert('FUZZ1337MARKER')\">xss</a>",
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: javascript: URI with CR in scheme",
			body:     "<a href=\"java\rscript:alert('FUZZ1337MARKER')\">xss</a>",
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: javascript: URI with mixed whitespace in scheme",
			body:     "<a href=\"j\ta\nv\ra\tscript:alert('FUZZ1337MARKER')\">xss</a>",
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: javascript: URI in formaction on button",
			body:     `<button formaction="javascript:void(FUZZ1337MARKER)">Go</button>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: javascript: URI in iframe src",
			body:     `<iframe src="javascript:alert('FUZZ1337MARKER')"></iframe>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: javascript: URI in object data attr",
			body:     `<object data="javascript:alert('FUZZ1337MARKER')"></object>`,
			marker:   marker,
			expected: ContextScript,
		},

		// --- #7086 Edge Case 2: JSON script blocks ---
		// <script type="application/json"> is non-executable data context.
		{
			name:     "#7086: script type=application/json is ScriptData",
			body:     `<script type="application/json">{"key": "FUZZ1337MARKER"}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},
		{
			name:     "#7086: script type=application/ld+json is ScriptData",
			body:     `<script type="application/ld+json">{"name": "FUZZ1337MARKER"}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},
		{
			name:     "#7086: script type=application/json with charset param is ScriptData",
			body:     `<script type="application/json; charset=utf-8">{"v": "FUZZ1337MARKER"}</script>`,
			marker:   marker,
			expected: ContextScriptData,
		},
		{
			name:     "#7086: mixed JSON and executable script blocks",
			body:     `<script type="application/json">{"safe": "data"}</script><script>var x = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},
		{
			name:     "#7086: script type empty string is executable",
			body:     `<script type="">var x = "FUZZ1337MARKER";</script>`,
			marker:   marker,
			expected: ContextScript,
		},

		// --- #7086 Edge Case 3: Case-insensitive reflection detection ---
		{
			name:     "#7086: marker fully uppercased in body still detected",
			body:     `<p>FUZZ1337MARKER appears here</p>`,
			marker:   "fuzz1337marker",
			expected: ContextHTMLBody,
		},
		{
			name:     "#7086: marker with random casing in script",
			body:     `<script>var x = "Fuzz1337Marker";</script>`,
			marker:   "FUZZ1337MARKER",
			expected: ContextScript,
		},
		{
			name:     "#7086: marker case-insensitive in attribute value",
			body:     `<input value="fUzZ1337mArKeR">`,
			marker:   "FUZZ1337MARKER",
			expected: ContextHTMLAttribute,
		},
		{
			name:     "#7086: marker case-insensitive in comment",
			body:     `<!-- fuzz1337marker -->`,
			marker:   "FUZZ1337MARKER",
			expected: ContextComment,
		},

		// --- #7086 Edge Case 4: srcdoc attribute context ---
		// srcdoc contains nested HTML that the browser parses independently.
		{
			name:     "#7086: srcdoc on iframe is HTMLBody context",
			body:     `<iframe srcdoc="<b>FUZZ1337MARKER</b>"></iframe>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "#7086: srcdoc with script injection is HTMLBody",
			body:     `<iframe srcdoc="<script>alert(FUZZ1337MARKER)</script>"></iframe>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
		{
			name:     "#7086: srcdoc with complex nested HTML",
			body:     `<iframe srcdoc="<html><body><img src=x onerror=alert(FUZZ1337MARKER)></body></html>"></iframe>`,
			marker:   marker,
			expected: ContextHTMLBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := AnalyzeReflectionContext(tc.body, tc.marker)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("got %s, want %s", result, tc.expected)
			}
		})
	}
}

func TestAnalyzeReflectionContext_NoPanic(t *testing.T) {
	// Ensure no panics on various malformed inputs.
	inputs := []string{
		`<`,
		`<>`,
		`</>`,
		`<<<>>>`,
		`<script`,
		`<script>`,
		`</script>`,
		`<!-- `,
		`<!-- -->`,
		`<div attr=">">`,
		`<div attr='`,
		string([]byte{0, 1, 2, 3, 4, 5}),
		`<script type="">FUZZ1337MARKER</script>`,
		`<` + string(make([]byte, 0)) + `>`,
	}

	for i, input := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on input %d: %v", i, r)
				}
			}()
			_, _ = AnalyzeReflectionContext(input, "FUZZ1337MARKER")
		}()
	}
}

func TestNormalizeURIScheme(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain javascript:", "javascript:alert(1)", "javascript:alert(1)"},
		{"tab in scheme", "java\tscript:alert(1)", "javascript:alert(1)"},
		{"newline in scheme", "java\nscript:alert(1)", "javascript:alert(1)"},
		{"CR in scheme", "java\rscript:alert(1)", "javascript:alert(1)"},
		{"mixed whitespace in scheme", "j\ta\nv\ra\tscript:x", "javascript:x"},
		{"leading spaces preserved by TrimSpace", "  javascript:x", "javascript:x"},
		{"mixed case", "JavaScript:alert(1)", "javascript:alert(1)"},
		{"data URI", "data:text/html,<h1>hi</h1>", "data:text/html,<h1>hi</h1>"},
		{"normal URL unchanged", "https://example.com", "https://example.com"},
		{"empty string", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeURIScheme(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeURIScheme(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestXSSContextString(t *testing.T) {
	tests := []struct {
		ctx      XSSContext
		expected string
	}{
		{ContextUnknown, "Unknown"},
		{ContextHTMLBody, "HTMLBody"},
		{ContextHTMLAttribute, "HTMLAttribute"},
		{ContextHTMLAttributeURL, "HTMLAttributeURL"},
		{ContextHTMLAttributeEvent, "HTMLAttributeEvent"},
		{ContextScript, "Script"},
		{ContextScriptData, "ScriptData"},
		{ContextStyle, "Style"},
		{ContextComment, "Comment"},
		{XSSContext(99), "XSSContext(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.ctx.String(); got != tc.expected {
				t.Errorf("got %q, want %q", got, tc.expected)
			}
		})
	}
}
