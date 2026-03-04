package xss

import (
	"testing"
)

func TestAnalyzer_Name(t *testing.T) {
	a := &Analyzer{}
	if a.Name() != "xss" {
		t.Errorf("Expected name 'xss', got '%s'", a.Name())
	}
}

func TestAnalyzer_ApplyInitialTransformation(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name     string
		data     string
		params   map[string]interface{}
		expected string
	}{
		{
			name:     "simple payload",
			data:     "<script>alert(1)</script>",
			params:   nil,
			expected: "<script>alert(1)</script>",
		},
		{
			name:     "payload with params",
			data:     "test",
			params:   map[string]interface{}{"key": "value"},
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.ApplyInitialTransformation(tt.data, tt.params)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestAnalyzer_containsJavaScriptURI(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name     string
		body     string
		payload  string
		expected bool
	}{
		{
			name:     "javascript URI present",
			body:     `<a href="javascript:alert(1)">click</a>`,
			payload:  "alert(1)",
			expected: true,
		},
		{
			name:     "javascript URI uppercase",
			body:     `<a href="JAVASCRIPT:alert(1)">click</a>`,
			payload:  "alert(1)",
			expected: true,
		},
		{
			name:     "no javascript URI",
			body:     `<a href="https://example.com">click</a>`,
			payload:  "alert(1)",
			expected: false,
		},
		{
			name:     "payload not in javascript URI",
			body:     `<div>alert(1)</div>`,
			payload:  "alert(1)",
			expected: false,
		},
		{
			name:     "javascript in data URI",
			body:     `<a href="data:text/javascript,alert(1)">click</a>`,
			payload:  "alert(1)",
			expected: false, // data: is not javascript:
		},
		{
			name:     "multiple payloads in javascript URI",
			body:     `<a href="javascript:alert(1)">click</a><script>alert(1)</script>`,
			payload:  "alert(1)",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.containsJavaScriptURI(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAnalyzer_containsSrcdoc(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name     string
		body     string
		payload  string
		expected bool
	}{
		{
			name:     "srcdoc present",
			body:     `<iframe srcdoc="<script>alert(1)</script>">`,
			payload:  "alert(1)",
			expected: true,
		},
		{
			name:     "srcdoc uppercase",
			body:     `<iframe SRCDOC="<script>alert(1)</script>">`,
			payload:  "alert(1)",
			expected: true,
		},
		{
			name:     "no srcdoc",
			body:     `<iframe src="test.html">`,
			payload:  "alert(1)",
			expected: false,
		},
		{
			name:     "srcdoc without payload",
			body:     `<iframe srcdoc="hello">`,
			payload:  "alert(1)",
			expected: false,
		},
		{
			name:     "srcdoc in iframe with spaces",
			body:     `<iframe   srcdoc  =  "test" >`,
			payload:  "test",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.containsSrcdoc(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestContextTypes(t *testing.T) {
	// Verify context type constants
	if ContextTypeNone != "none" {
		t.Errorf("ContextTypeNone should be 'none'")
	}
	if ContextTypeHTMLContent != "html-content" {
		t.Errorf("ContextTypeHTMLContent should be 'html-content'")
	}
	if ContextTypeHTMLAttribute != "html-attribute" {
		t.Errorf("ContextTypeHTMLAttribute should be 'html-attribute'")
	}
	if ContextTypeJavaScript != "javascript" {
		t.Errorf("ContextTypeJavaScript should be 'javascript'")
	}
	if ContextTypeJavaScriptURI != "javascript-uri" {
		t.Errorf("ContextTypeJavaScriptURI should be 'javascript-uri'")
	}
	if ContextTypeSrcDoc != "srcdoc" {
		t.Errorf("ContextTypeSrcDoc should be 'srcdoc'")
	}
	if ContextTypeStyle != "style" {
		t.Errorf("ContextTypeStyle should be 'style'")
	}
	if ContextTypeURL != "url" {
		t.Errorf("ContextTypeURL should be 'url'")
	}
	if ContextTypeEventHandler != "event-handler" {
		t.Errorf("ContextTypeEventHandler should be 'event-handler'")
	}
}

func TestAnalyzer_analyzeHTMLContext(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name     string
		body     string
		payload  string
		expected ContextType
	}{
		{
			name:     "HTML content",
			body:     `<html><body><div>test alert(1) payload</div></body></html>`,
			payload:  "alert(1)",
			expected: ContextTypeHTMLContent,
		},
		{
			name:     "Event handler attribute",
			body:     `<html><body><button onclick="alert(1)">click</button></body></html>`,
			payload:  "alert(1)",
			expected: ContextTypeEventHandler,
		},
		{
			name:     "HTML attribute",
			body:     `<html><body><input value="test alert(1)">`,
			payload:  "alert(1)",
			expected: ContextTypeHTMLAttribute,
		},
		{
			name:     "URL attribute",
			body:     `<html><body><a href="/test">test</a></body></html>`,
			payload:  "/test",
			expected: ContextTypeURL,
		},
		{
			name:     "Script tag content",
			body:     `<html><body><script>var x = "alert(1)";</script></body></html>`,
			payload:  "alert(1)",
			expected: ContextTypeJavaScript,
		},
		{
			name:     "Style content",
			body:     `<html><body><style>div { color: red; }</style></body></html>`,
			payload:  "color: red",
			expected: ContextTypeStyle,
		},
		{
			name:     "Style attribute",
			body:     `<html><body><div style="color: red;">test</div></body></html>`,
			payload:  "color: red",
			expected: ContextTypeStyle,
		},
		{
			name:     "Payload not in body",
			body:     `<html><body><div>Hello World</div></body></html>`,
			payload:  "notfound",
			expected: ContextTypeNone,
		},
		{
			name:     "javascript: URI in href",
			body:     `<html><body><a href="javascript:alert(1)">test</a></body></html>`,
			payload:  "alert(1)",
			expected: ContextTypeJavaScriptURI,
		},
		{
			name:     "srcdoc attribute",
			body:     `<html><body><iframe srcdoc="<script>alert(1)</script>"></iframe></body></html>`,
			payload:  "alert(1)",
			expected: ContextTypeSrcDoc,
		},
		{
			name:     "vbscript URI in href",
			body:     `<html><body><a href="vbscript:msgbox(1)">test</a></body></html>`,
			payload:  "msgbox(1)",
			expected: ContextTypeJavaScriptURI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.analyzeHTMLContext(tt.body, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
