package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextAnalyzer_JavascriptURI(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name       string
		response   string
		reflection string
		expected   Context
	}{
		{
			name:       "javascript URI in href",
			response:   `<a href="javascript:alert('XSS')">click</a>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "javascript URI case insensitive",
			response:   `<a href="JavaScript:alert('XSS')">click</a>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "javascript URI with spaces",
			response:   `<a href="javascript : alert('XSS')">click</a>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "javascript URI in src",
			response:   `<img src="javascript:alert('XSS')">`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "no javascript URI",
			response:   `<a href="https://example.com">click</a>`,
			reflection: "example",
			expected:   ContextUnknown,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeContext(tt.response, tt.reflection)
			require.Equal(t, tt.expected, result, "Context mismatch")
		})
	}
}

func TestContextAnalyzer_ScriptBlocks(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name       string
		response   string
		reflection string
		expected   Context
	}{
		{
			name:       "regular script block",
			response:   `<script>alert('XSS')</script>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "JSON script block (not executable)",
			response:   `<script type="application/json">{"key": "value"}</script>`,
			reflection: "value",
			expected:   ContextUnknown,
		},
		{
			name:       "JSON script block single quotes",
			response:   `<script type='application/json'>{"key": "value"}</script>`,
			reflection: "value",
			expected:   ContextUnknown,
		},
		{
			name:       "script block case insensitive",
			response:   `<SCRIPT>alert('XSS')</SCRIPT>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "script with spaces",
			response:   `< script >alert('XSS')</ script >`,
			reflection: "alert",
			expected:   ContextScript,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeContext(tt.response, tt.reflection)
			require.Equal(t, tt.expected, result, "Context mismatch")
		})
	}
}

func TestContextAnalyzer_Srcdoc(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name       string
		response   string
		reflection string
		expected   Context
	}{
		{
			name:       "srcdoc attribute",
			response:   `<iframe srcdoc="<img src=x onerror=alert(1)>"></iframe>`,
			reflection: "img",
			expected:   ContextHTML,
		},
		{
			name:       "srcdoc case insensitive",
			response:   `<iframe SRCDOC="<img src=x onerror=alert(1)>"></iframe>`,
			reflection: "img",
			expected:   ContextHTML,
		},
		{
			name:       "srcdoc with spaces",
			response:   `<iframe srcdoc = "<img src=x onerror=alert(1)>"></iframe>`,
			reflection: "img",
			expected:   ContextHTML,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeContext(tt.response, tt.reflection)
			require.Equal(t, tt.expected, result, "Context mismatch")
		})
	}
}

func TestContextAnalyzer_CaseInsensitiveReflection(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name       string
		response   string
		reflection string
		expected   bool
	}{
		{
			name:       "exact match",
			response:   `<img src="test">`,
			reflection: "test",
			expected:   true,
		},
		{
			name:       "case mismatch",
			response:   `<img src="TEST">`,
			reflection: "test",
			expected:   true,
		},
		{
			name:       "mixed case",
			response:   `<img src="TeSt">`,
			reflection: "test",
			expected:   true,
		},
		{
			name:       "no match",
			response:   `<img src="other">`,
			reflection: "test",
			expected:   false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.IsCaseInsensitiveMatch(tt.response, tt.reflection)
			require.Equal(t, tt.expected, result, "Match result mismatch")
		})
	}
}

func TestContextAnalyzer_HTMLAttribute(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name       string
		response   string
		reflection string
		expected   Context
	}{
		{
			name:       "simple attribute",
			response:   `<div class="test">content</div>`,
			reflection: "test",
			expected:   ContextAttribute,
		},
		{
			name:       "img src attribute",
			response:   `<img src="test.png">`,
			reflection: "test.png",
			expected:   ContextAttribute,
		},
		{
			name:       "a href attribute",
			response:   `<a href="https://example.com">link</a>`,
			reflection: "https://example.com",
			expected:   ContextAttribute,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeContext(tt.response, tt.reflection)
			require.Equal(t, tt.expected, result, "Context mismatch")
		})
	}
}

func TestContextAnalyzer_IsExecutableContext(t *testing.T) {
	tests := []struct {
		name     string
		context  Context
		expected bool
	}{
		{"ContextScript", ContextScript, true},
		{"ContextHTML", ContextHTML, true},
		{"ContextURL", ContextURL, true},
		{"ContextAttribute", ContextAttribute, false},
		{"ContextCSS", ContextCSS, false},
		{"ContextUnknown", ContextUnknown, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsExecutableContext(tt.context)
			require.Equal(t, tt.expected, result, "Executable context mismatch")
		})
	}
}

func TestContextAnalyzer_ComplexScenarios(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name       string
		response   string
		reflection string
		expected   Context
	}{
		{
			name:       "javascript in event handler",
			response:   `<button onclick="javascript:alert('XSS')">click</button>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "multiple contexts - javascript takes precedence",
			response:   `<div><a href="javascript:alert(1)">link</a><img src="test.png"></div>`,
			reflection: "alert",
			expected:   ContextScript,
		},
		{
			name:       "nested script tags",
			response:   `<script>var x = "<script>nested</script>";</script>`,
			reflection: "nested",
			expected:   ContextScript,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeContext(tt.response, tt.reflection)
			require.Equal(t, tt.expected, result, "Context mismatch")
		})
	}
}
