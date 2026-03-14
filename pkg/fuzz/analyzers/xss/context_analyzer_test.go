package xss

import (
	"testing"
)

func TestFindContext(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		marker   string
		expected string
	}{
		{
			name:     "html text",
			body:     "<div>MARKER</div>",
			marker:   "MARKER",
			expected: "html_text",
		},
		{
			name:     "html attribute",
			body:     `<div title="MARKER">`,
			marker:   "MARKER",
			expected: "html_attribute",
		},
		{
			name:     "event handler",
			body:     `<div onclick="MARKER">`,
			marker:   "MARKER",
			expected: "event_handler",
		},
		{
			name:     "url attribute href",
			body:     `<a href="MARKER">`,
			marker:   "MARKER",
			expected: "url_attribute",
		},
		{
			name:     "url attribute src",
			body:     `<img src="MARKER">`,
			marker:   "MARKER",
			expected: "url_attribute",
		},
		{
			name:     "script executable",
			body:     `<script>MARKER</script>`,
			marker:   "MARKER",
			expected: "script_executable",
		},
		{
			name:     "script data application/json",
			body:     `<script type="application/json">MARKER</script>`,
			marker:   "MARKER",
			expected: "script_data",
		},
		{
			name:     "style",
			body:     `<style>MARKER</style>`,
			marker:   "MARKER",
			expected: "style",
		},
		{
			name:     "html comment",
			body:     `<!-- MARKER -->`,
			marker:   "MARKER",
			expected: "html_comment",
		},
		{
			name:     "unknown",
			body:     `<body>something entirely different</body>`,
			marker:   "MARKER",
			expected: "unknown",
		},
		{
			name:     "nested tags",
			body:     `<html><body><div id="parent"><a href="MARKER">link</a></div></body></html>`,
			marker:   "MARKER",
			expected: "url_attribute",
		},
		{
			name:     "multiple attributes",
			body:     `<input type="text" class="input-field" value="MARKER" required>`,
			marker:   "MARKER",
			expected: "html_attribute",
		},
		{
			name:     "encoded HTML entities in text",
			body:     `<div>&lt;MARKER&gt;</div>`,
			marker:   "MARKER",
			expected: "html_text",
		},
		{
			name:     "whitespace variations",
			body:     `<a   href  =  "MARKER"   >`,
			marker:   "MARKER",
			expected: "url_attribute",
		},
		{
			name:     "case insensitive attributes",
			body:     `<a HrEf="MARKER">`,
			marker:   "MARKER",
			expected: "url_attribute",
		},
		{
			name:     "case insensitive scripts",
			body:     `<SCript tyPE="aPpliCATiOn/JSoN">MARKER</SCript>`,
			marker:   "MARKER",
			expected: "script_data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := FindContext(tt.body, tt.marker)
			if actual != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, actual)
			}
		})
	}
}
