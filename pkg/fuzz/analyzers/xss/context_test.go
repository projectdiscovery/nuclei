package xss

import (
	"testing"
)

func TestDetectContext(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		marker   string
		expected ContextType
	}{
		{
			name:     "marker not present",
			body:     `<html><body><p>Hello world</p></body></html>`,
			marker:   "nuclei12345",
			expected: ContextNone,
		},
		{
			name:     "empty body",
			body:     "",
			marker:   "nuclei12345",
			expected: ContextNone,
		},
		{
			name:     "reflected in tag body",
			body:     `<html><body><div>nuclei12345</div></body></html>`,
			marker:   "nuclei12345",
			expected: ContextHTML,
		},
		{
			name:     "reflected in paragraph text",
			body:     `<p>some text nuclei12345 more text</p>`,
			marker:   "nuclei12345",
			expected: ContextHTML,
		},
		{
			name:     "reflected in nested tag body",
			body:     `<html><body><div><span><b>nuclei12345</b></span></div></body></html>`,
			marker:   "nuclei12345",
			expected: ContextHTML,
		},
		{
			name:     "reflected in attribute value",
			body:     `<img src="nuclei12345">`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "reflected in href attribute",
			body:     `<a href="https://example.com/nuclei12345">link</a>`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "reflected in input value",
			body:     `<input type="text" value="nuclei12345">`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "reflected in class attribute",
			body:     `<div class="foo nuclei12345 bar">text</div>`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "reflected in script text",
			body:     `<script>var x = "nuclei12345";</script>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in inline script",
			body:     `<html><head><script>alert('nuclei12345')</script></head></html>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in onclick event handler",
			body:     `<button onclick="alert('nuclei12345')">Click</button>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in onmouseover event handler",
			body:     `<div onmouseover="track('nuclei12345')">hover</div>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in onerror event handler",
			body:     `<img src=x onerror="alert('nuclei12345')">`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in onfocus event handler",
			body:     `<input onfocus="doStuff('nuclei12345')" autofocus>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in mixed case event handler",
			body:     `<div ONCLICK="alert('nuclei12345')">text</div>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in comment",
			body:     `<html><!-- nuclei12345 --><body></body></html>`,
			marker:   "nuclei12345",
			expected: ContextComment,
		},
		{
			name:     "reflected in multi-line comment",
			body:     "<!-- some debug info\nnuclei12345\nend -->",
			marker:   "nuclei12345",
			expected: ContextComment,
		},
		{
			name:     "reflected in both attribute and script — script wins",
			body:     `<input value="nuclei12345"><script>var y = "nuclei12345";</script>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "reflected in both html body and attribute — attribute wins",
			body:     `<div title="nuclei12345">nuclei12345</div>`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "reflected in comment, html, attribute, and script — script wins",
			body:     `<!-- nuclei12345 --><div class="nuclei12345">nuclei12345</div><script>nuclei12345</script>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "marker in attribute name (unusual reflection)",
			body:     `<div nuclei12345="value">text</div>`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "self-closing tag with marker in attribute",
			body:     `<br data-val="nuclei12345"/>`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "marker spans partial word in body",
			body:     `<p>foodnuclei12345bar</p>`,
			marker:   "nuclei12345",
			expected: ContextHTML,
		},
		{
			name:     "non-standard event handler is treated as attribute",
			body:     `<div data-onclick="nuclei12345">text</div>`,
			marker:   "nuclei12345",
			expected: ContextAttribute,
		},
		{
			name:     "script with mixed case tag",
			body:     `<SCRIPT>var z = "nuclei12345";</SCRIPT>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "multiple scripts, marker in second",
			body:     `<script>var a = 1;</script><p>safe</p><script>var b = "nuclei12345";</script>`,
			marker:   "nuclei12345",
			expected: ContextScript,
		},
		{
			name:     "marker in style tag body is html context",
			body:     `<style>.nuclei12345 { color: red; }</style>`,
			marker:   "nuclei12345",
			expected: ContextHTML,
		},
		{
			name:     "self-closing script tag does not affect subsequent text",
			body:     `<script src="external.js"/><div>nuclei12345</div>`,
			marker:   "nuclei12345",
			expected: ContextHTML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectContext(tt.body, tt.marker)
			if got != tt.expected {
				t.Errorf("DetectContext() = %v (%s), want %v (%s)",
					got, got.String(), tt.expected, tt.expected.String())
			}
		})
	}
}

func TestIsEventHandler(t *testing.T) {
	tests := []struct {
		attr     string
		expected bool
	}{
		{"onclick", true},
		{"ONCLICK", true},
		{"OnClick", true},
		{"onmouseover", true},
		{"onerror", true},
		{"onload", true},
		{"onanimationiteration", true},
		{"onfocusin", true},
		{"onpointerdown", true},
		{"class", false},
		{"href", false},
		{"src", false},
		{"data-onclick", false},
		{"onnonexistent", false},
		{"on", false},
	}

	for _, tt := range tests {
		t.Run(tt.attr, func(t *testing.T) {
			got := isEventHandler([]byte(tt.attr))
			if got != tt.expected {
				t.Errorf("isEventHandler(%q) = %v, want %v", tt.attr, got, tt.expected)
			}
		})
	}
}

func TestContextTypeString(t *testing.T) {
	tests := []struct {
		ctx      ContextType
		expected string
	}{
		{ContextNone, "none"},
		{ContextComment, "comment"},
		{ContextHTML, "html_tag"},
		{ContextAttribute, "attribute"},
		{ContextScript, "script"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.ctx.String(); got != tt.expected {
				t.Errorf("ContextType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func BenchmarkDetectContext_NoReflection(b *testing.B) {
	body := `<html><head><title>Test</title></head><body><div class="container"><p>Hello world</p></div></body></html>`
	marker := "nucleiXYZ12345"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectContext(body, marker)
	}
}

func BenchmarkDetectContext_HTMLContext(b *testing.B) {
	body := `<html><body><div>nucleiXYZ12345</div></body></html>`
	marker := "nucleiXYZ12345"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectContext(body, marker)
	}
}

func BenchmarkDetectContext_ScriptContext(b *testing.B) {
	body := `<html><body><script>var x = "nucleiXYZ12345";</script></body></html>`
	marker := "nucleiXYZ12345"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectContext(body, marker)
	}
}

func BenchmarkDetectContext_AttributeContext(b *testing.B) {
	body := `<html><body><input type="text" value="nucleiXYZ12345"></body></html>`
	marker := "nucleiXYZ12345"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectContext(body, marker)
	}
}

func BenchmarkDetectContext_LargePage(b *testing.B) {
	var page string
	for i := 0; i < 100; i++ {
		page += `<div class="item"><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>`
	}
	page += `<script>var token = "nucleiXYZ12345";</script></body></html>`
	marker := "nucleiXYZ12345"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectContext(page, marker)
	}
}
