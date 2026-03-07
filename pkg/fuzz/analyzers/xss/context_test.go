package xss

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestIsJavascriptURI(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name     string
		html     string
		expected bool
	}{
		{
			name:     "javascript href",
			html:     `<a href="javascript:alert('XSS')">Click</a>`,
			expected: true,
		},
		{
			name:     "javascript uppercase",
			html:     `<a HREF="JAVASCRIPT:alert(1)">Click</a>`,
			expected: true,
		},
		{
			name:     "javascript with whitespace",
			html:     `<a href="  javascript:alert(1)">Click</a>`,
			expected: true,
		},
		{
			name:     "http href",
			html:     `<a href="http://example.com">Click</a>`,
			expected: false,
		},
		{
			name:     "https href",
			html:     `<a href="https://example.com">Click</a>`,
			expected: false,
		},
		{
			name:     "javascript in text content",
			html:     `<p>This mentions javascript: in text</p>`,
			expected: false,
		},
		{
			name:     "javascript src",
			html:     `<script src="javascript:alert(1)"></script>`,
			expected: true,
		},
		// FIX: Add tests for bypass attempts (CWE-79)
		{
			name:     "javascript with tab bypass",
			html:     `<a href="java&#x09;script:alert(1)">Click</a>`,
			expected: true,
		},
		{
			name:     "javascript with newline bypass",
			html:     `<a href="java&#x0A;script:alert(1)">Click</a>`,
			expected: true,
		},
		{
			name:     "javascript with carriage return bypass",
			html:     `<a href="java&#x0D;script:alert(1)">Click</a>`,
			expected: true,
		},
		{
			name:     "javascript with null byte bypass",
			html:     `<a href="java&#x00;script:alert(1)">Click</a>`,
			expected: true,
		},
		{
			name:     "javascript with multiple control chars",
			html:     `<a href="j&#x09;a&#x0A;v&#x0D;a&#x00;script:alert(1)">Click</a>`,
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer.tokenizer = html.NewTokenizer(strings.NewReader(tt.html))
			for {
				tok := analyzer.tokenizer.Next()
				if tok == html.ErrorToken {
					break
				}
				token := analyzer.tokenizer.Token()
				if token.Type == html.StartTagToken {
					result := analyzer.isJavascriptURI(token)
					if result != tt.expected {
						t.Errorf("isJavascriptURI() = %v, want %v", result, tt.expected)
					}
					return
				}
			}
		})
	}
}

func TestNormalizeJavascriptURI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal javascript:",
			input:    "javascript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with leading space",
			input:    "  javascript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with tab in middle",
			input:    "java\tscript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with newline in middle",
			input:    "java\nscript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with carriage return in middle",
			input:    "java\rscript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with null byte in middle",
			input:    "java\x00script:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with multiple control chars",
			input:    "j\ta\nv\ra\x00script:alert(1)",
			expected: "javascript:alert(1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeJavascriptURI(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeJavascriptURI() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestNormalizeJavascriptURI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal javascript:",
			input:    "javascript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with leading space",
			input:    "  javascript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with tab in middle",
			input:    "java\tscript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with newline in middle",
			input:    "java\nscript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with carriage return in middle",
			input:    "java\rscript:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with null byte in middle",
			input:    "java\x00script:alert(1)",
			expected: "javascript:alert(1)",
		},
		{
			name:     "with multiple control chars",
			input:    "j\ta\nv\ra\x00script:alert(1)",
			expected: "javascript:alert(1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeJavascriptURI(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeJavascriptURI() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsJSONScript(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name     string
		html     string
		expected bool
	}{
		{
			name:     "application/json",
			html:     `<script type="application/json">{"key": "value"}</script>`,
			expected: true,
		},
		{
			name:     "application/ld+json",
			html:     `<script type="application/ld+json">{}</script>`,
			expected: true,
		},
		{
			name:     "regular script",
			html:     `<script>alert(1)</script>`,
			expected: false,
		},
		{
			name:     "text/javascript",
			html:     `<script type="text/javascript">alert(1)</script>`,
			expected: false,
		},
		{
			name:     "no type attribute",
			html:     `<script>var x = 1;</script>`,
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer.tokenizer = html.NewTokenizer(strings.NewReader(tt.html))
			for {
				tok := analyzer.tokenizer.Next()
				if tok == html.ErrorToken {
					break
				}
				token := analyzer.tokenizer.Token()
				if token.Type == html.StartTagToken {
					result := analyzer.isJSONScript(token)
					if result != tt.expected {
						t.Errorf("isJSONScript() = %v, want %v", result, tt.expected)
					}
					return
				}
			}
		})
	}
}

func TestAnalyzeContext(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	tests := []struct {
		name        string
		response    string
		canary      string
		expectedCtx ContextType
	}{
		{
			name:        "javascript URI detection",
			response:    `<a href="javascript:alert('XSS_CANARY')">Click</a>`,
			canary:      "XSS_CANARY",
			expectedCtx: ContextJavascriptURI,
		},
		// FIX: Add test for bypass detection
		{
			name:        "javascript URI with tab bypass",
			response:    `<a href="java&#x09;script:alert('XSS_CANARY')">Click</a>`,
			canary:      "XSS_CANARY",
			expectedCtx: ContextJavascriptURI,
		},
		{
			name:        "JSON script detection",
			response:    `<script type="application/json">{"canary": "XSS_CANARY"}</script>`,
			canary:      "XSS_CANARY",
			expectedCtx: ContextJSON,
		},
		{
			name:        "HTML text context",
			response:    `<p>Hello XSS_CANARY World</p>`,
			canary:      "XSS_CANARY",
			expectedCtx: ContextHTMLText,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := analyzer.AnalyzeContext(tt.response, tt.canary)
			if err != nil {
				t.Errorf("AnalyzeContext() error = %v", err)
			}
			if ctx != tt.expectedCtx {
				t.Errorf("AnalyzeContext() = %v, want %v", ctx, tt.expectedCtx)
			}
		})
	}
}
