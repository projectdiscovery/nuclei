package xss

import (
	"strings"
	"testing"
)

func TestXSSContextAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		content  string
		expected ContextType
	}{
		{
			name:     "HTML text context",
			payload:  "alert(1)",
			content:  "<div>alert(1)</div>",
			expected: ContextHTMLText,
		},
		{
			name:     "HTML attribute context",
			payload:  "javascript:alert(1)",
			content:  `<a href="javascript:alert(1)">link</a>`,
			expected: ContextURL,
		},
		{
			name:     "JavaScript event handler",
			payload:  "alert(1)",
			content:  `<img src="x" onerror="alert(1)" />`,
			expected: ContextJavaScript,
		},
		{
			name:     "Script block context",
			payload:  "alert(1)",
			content:  "<script>alert(1)</script>",
			expected: ContextScriptBlock,
		},
		{
			name:     "Style block context",
			payload:  "body{background:red}",
			content:  "<style>body{background:red}</style>",
			expected: ContextStyleBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewXSSContextAnalyzer(tt.payload)
			contexts := analyzer.Analyze(tt.content)
			
			if len(contexts) == 0 {
				t.Errorf("Expected to find context, but got none")
				return
			}
			
			found := false
			for _, ctx := range contexts {
				if ctx.Type == tt.expected {
					found = true
					break
				}
			}
			
			if !found {
				t.Errorf("Expected context type %v, but got %v", tt.expected, contexts[0].Type)
			}
		})
	}
}

func TestGetSmartPayload(t *testing.T) {
	analyzer := NewXSSContextAnalyzer("<script>alert(1)</script>")
	
	contexts := []ContextAnalysis{
		{
			Type:       ContextHTMLText,
			Confidence: 0.9,
			Suggestions: []string{"<script>alert(1)</script>"},
		},
	}
	
	payload := analyzer.GetSmartPayload(contexts)
	if payload == "" {
		t.Error("Expected non-empty payload")
	}
}

func TestIsEscaped(t *testing.T) {
	analyzer := NewXSSContextAnalyzer("<script>")
	
	tests := []struct {
		text     string
		expected bool
	}{
		{"<script>", false},
		{"&lt;script&gt;", true},
		{"&#60;script&#62;", true},
	}
	
	for _, tt := range tests {
		result := analyzer.isEscaped(tt.text, "<script>")
		if result != tt.expected {
			t.Errorf("isEscaped(%q) = %v, expected %v", tt.text, result, tt.expected)
		}
	}
}

func TestIsURLAttribute(t *testing.T) {
	analyzer := NewXSSContextAnalyzer("")
	
	urlAttrs := []string{"href", "src", "action", "data"}
	nonUrlAttrs := []string{"class", "id", "style", "onclick"}
	
	for _, attr := range urlAttrs {
		if !analyzer.isURLAttribute(attr) {
			t.Errorf("Expected %s to be a URL attribute", attr)
		}
	}
	
	for _, attr := range nonUrlAttrs {
		if analyzer.isURLAttribute(attr) {
			t.Errorf("Expected %s not to be a URL attribute", attr)
		}
	}
}

func TestIsEventHandler(t *testing.T) {
	analyzer := NewXSSContextAnalyzer("")
	
	eventHandlers := []string{"onclick", "onerror", "onload", "onmouseover"}
	nonEventHandlers := []string{"class", "id", "href", "src"}
	
	for _, attr := range eventHandlers {
		if !analyzer.isEventHandler(attr) {
			t.Errorf("Expected %s to be an event handler", attr)
		}
	}
	
	for _, attr := range nonEventHandlers {
		if analyzer.isEventHandler(attr) {
			t.Errorf("Expected %s not to be an event handler", attr)
		}
	}
}

func TestContextTypeString(t *testing.T) {
	tests := []struct {
		ctx      ContextType
		expected string
	}{
		{ContextHTMLText, "html-text"},
		{ContextJavaScript, "javascript"},
		{ContextURL, "url"},
		{ContextUnknown, "unknown"},
	}
	
	for _, tt := range tests {
		result := tt.ctx.String()
		if result != tt.expected {
			t.Errorf("ContextType(%d).String() = %q, expected %q", tt.ctx, result, tt.expected)
		}
	}
}

func BenchmarkXSSContextAnalyzer(b *testing.B) {
	analyzer := NewXSSContextAnalyzer("<script>alert(1)</script>")
	content := "<html><body><div>" + strings.Repeat("<script>alert(1)</script>", 100) + "</div></body></html>"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(content)
	}
}
