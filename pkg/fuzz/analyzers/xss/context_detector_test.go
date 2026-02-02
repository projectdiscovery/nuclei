package xss

import (
	"strings"
	"testing"
)

func TestDetectHTMLBodyContext(t *testing.T) {
	body := `<html><body><div>Hello xSs9K7j world</div></body></html>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextHTMLBody {
		t.Errorf("Expected HTML_BODY context, got %v", reflections[0].Context)
	}
}

func TestDetectAttributeQuotedContext(t *testing.T) {
	body := `<input type="text" value="xSs9K7j">`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextHTMLAttributeQuoted {
		t.Errorf("Expected HTML_ATTRIBUTE_QUOTED, got %v", reflections[0].Context)
	}

	if reflections[0].QuoteChar != "\"" {
		t.Errorf("Expected quote char \", got %q", reflections[0].QuoteChar)
	}
}

func TestDetectAttributeSingleQuotedContext(t *testing.T) {
	body := `<input type='text' value='xSs9K7j'>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextHTMLAttributeQuoted {
		t.Errorf("Expected HTML_ATTRIBUTE_QUOTED, got %v", reflections[0].Context)
	}

	if reflections[0].QuoteChar != "'" {
		t.Errorf("Expected quote char ', got %q", reflections[0].QuoteChar)
	}
}

func TestDetectAttributeUnquotedContext(t *testing.T) {
	body := `<input type=text value=xSs9K7j>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextHTMLAttributeUnquoted {
		t.Errorf("Expected HTML_ATTRIBUTE_UNQUOTED, got %v", reflections[0].Context)
	}
}

func TestDetectScriptStringContext(t *testing.T) {
	body := `<script>var x = "xSs9K7j";</script>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextScriptString {
		t.Errorf("Expected SCRIPT_STRING, got %v", reflections[0].Context)
	}
}

func TestDetectScriptBlockContext(t *testing.T) {
	body := `<script>var x = xSs9K7j;</script>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextScriptBlock {
		t.Errorf("Expected SCRIPT_BLOCK, got %v", reflections[0].Context)
	}
}

func TestDetectHTMLCommentContext(t *testing.T) {
	body := `<html><!-- Comment with xSs9K7j --></html>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextHTMLComment {
		t.Errorf("Expected HTML_COMMENT, got %v", reflections[0].Context)
	}
}

func TestDetectStyleBlockContext(t *testing.T) {
	body := `<style>.test { color: xSs9K7j; }</style>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection, got %d", len(reflections))
	}

	if reflections[0].Context != ContextStyleBlock {
		t.Errorf("Expected STYLE_BLOCK, got %v", reflections[0].Context)
	}
}

func TestDetectMultipleReflections(t *testing.T) {
	body := `<div>xSs9K7j</div><input value="xSs9K7j"><script>var x = "xSs9K7j";</script>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 3 {
		t.Fatalf("Expected 3 reflections, got %d", len(reflections))
	}

	// Check contexts
	if reflections[0].Context != ContextHTMLBody {
		t.Errorf("First reflection: expected HTML_BODY, got %v", reflections[0].Context)
	}

	if reflections[1].Context != ContextHTMLAttributeQuoted {
		t.Errorf("Second reflection: expected HTML_ATTRIBUTE_QUOTED, got %v", reflections[1].Context)
	}

	if reflections[2].Context != ContextScriptString {
		t.Errorf("Third reflection: expected SCRIPT_STRING, got %v", reflections[2].Context)
	}
}

func TestDetectAvailableCharacters(t *testing.T) {
	canary := "xSs9K7j<>'\"/())"

	// Test unencoded
	chars := detectAvailableCharacters(canary, canary)
	if !chars.LessThan || !chars.GreaterThan || !chars.SingleQuote || !chars.DoubleQuote || !chars.Slash {
		t.Error("All special chars should be available when unencoded")
	}

	// Test encoded
	encoded := "xSs9K7j&lt;&gt;&apos;&quot;/()"
	chars = detectAvailableCharacters(encoded, canary)
	if chars.LessThan || chars.GreaterThan || chars.SingleQuote || chars.DoubleQuote {
		t.Error("Encoded chars should not be available")
	}
	if !chars.Slash {
		t.Error("Slash should still be available")
	}
}

func TestCaseInsensitiveCanaryDetection(t *testing.T) {
	body := `<div>XSS9K7J</div>`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection (case-insensitive), got %d", len(reflections))
	}
}

func TestBrokenHTMLHandling(t *testing.T) {
	// Missing closing tag
	body := `<div>xSs9K7j`
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	if len(reflections) != 1 {
		t.Fatalf("Expected 1 reflection in broken HTML, got %d", len(reflections))
	}

	// Should still detect as HTML body
	if reflections[0].Context != ContextHTMLBody {
		t.Errorf("Expected HTML_BODY for broken HTML, got %v", reflections[0].Context)
	}
}

func TestReflectionLimit(t *testing.T) {
	// Create body with more than 10 reflections
	body := strings.Repeat("<div>xSs9K7j</div>", 15)
	canary := "xSs9K7j"

	reflections := DetectContexts(body, canary)

	// Should be limited to 10
	if len(reflections) > 10 {
		t.Errorf("Expected max 10 reflections, got %d", len(reflections))
	}
}

func TestDetectCaseInsensitiveTags(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		canary   string
		expected ContextType
	}{
		{
			name:     "Uppercase SCRIPT tag",
			body:     `<SCRIPT>var x = "xSs9K7j";</SCRIPT>`,
			canary:   "xSs9K7j",
			expected: ContextScriptString,
		},
		{
			name:     "Mixed case Script tag",
			body:     `<Script>var x = xSs9K7j;</Script>`,
			canary:   "xSs9K7j",
			expected: ContextScriptBlock,
		},
		{
			name:     "Uppercase STYLE tag",
			body:     `<STYLE>.x { color: xSs9K7j; }</STYLE>`,
			canary:   "xSs9K7j",
			expected: ContextStyleBlock,
		},
		{
			name:     "Mixed case Comment",
			body:     `<!-- Comment with xSs9K7j -->`,
			canary:   "xSs9K7j",
			expected: ContextHTMLComment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflections := DetectContexts(tt.body, tt.canary)
			if len(reflections) != 1 {
				t.Fatalf("Expected 1 reflection, got %d", len(reflections))
			}
			if reflections[0].Context != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, reflections[0].Context)
			}
		})
	}
}

func TestDetectURLAttributeContext(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		canary    string
		expectURL bool
	}{
		{
			name:      "href attribute",
			body:      `<a href="xSs9K7j">link</a>`,
			canary:    "xSs9K7j",
			expectURL: true,
		},
		{
			name:      "src attribute",
			body:      `<img src="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: true,
		},
		{
			name:      "action attribute",
			body:      `<form action="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: true,
		},
		{
			name:      "data attribute",
			body:      `<object data="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: true,
		},
		{
			name:      "formaction attribute",
			body:      `<button formaction="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: true,
		},
		{
			name:      "poster attribute",
			body:      `<video poster="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: true,
		},
		{
			name:      "regular attribute (not URL)",
			body:      `<input id="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: false,
		},
		{
			name:      "value attribute (not URL)",
			body:      `<input value="xSs9K7j">`,
			canary:    "xSs9K7j",
			expectURL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflections := DetectContexts(tt.body, tt.canary)
			if len(reflections) != 1 {
				t.Fatalf("Expected 1 reflection, got %d", len(reflections))
			}

			if tt.expectURL {
				if reflections[0].Context != ContextURLAttribute {
					t.Errorf("Expected ContextURLAttribute, got %v", reflections[0].Context)
				}
			} else {
				if reflections[0].Context == ContextURLAttribute {
					t.Errorf("Expected non-URL context, got ContextURLAttribute")
				}
			}
		})
	}
}

func TestDetectScriptInsideSVG(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		canary   string
		expected ContextType
	}{
		{
			name:     "Script string inside SVG",
			body:     `<svg><script>var x = "xSs9K7j";</script></svg>`,
			canary:   "xSs9K7j",
			expected: ContextScriptString,
		},
		{
			name:     "Script block inside SVG",
			body:     `<svg><script>var x = xSs9K7j;</script></svg>`,
			canary:   "xSs9K7j",
			expected: ContextScriptBlock,
		},
		{
			name:     "Nested SVG with script",
			body:     `<div><svg xmlns="http://www.w3.org/2000/svg"><script>alert("xSs9K7j")</script></svg></div>`,
			canary:   "xSs9K7j",
			expected: ContextScriptString,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflections := DetectContexts(tt.body, tt.canary)
			if len(reflections) != 1 {
				t.Fatalf("Expected 1 reflection, got %d", len(reflections))
			}
			if reflections[0].Context != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, reflections[0].Context)
			}
		})
	}
}

func TestDetectCDATASection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		canary   string
		expected ContextType
	}{
		{
			name:     "CDATA in script with string",
			body:     `<script>//<![CDATA[var x = "xSs9K7j";//]]></script>`,
			canary:   "xSs9K7j",
			expected: ContextScriptString,
		},
		{
			name:     "CDATA in script block",
			body:     `<script><![CDATA[var x = xSs9K7j;]]></script>`,
			canary:   "xSs9K7j",
			expected: ContextScriptBlock,
		},
		{
			name: "XHTML style CDATA",
			body: `<script type="text/javascript">//<![CDATA[
				var name = "xSs9K7j";
			//]]></script>`,
			canary:   "xSs9K7j",
			expected: ContextScriptString,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflections := DetectContexts(tt.body, tt.canary)
			if len(reflections) != 1 {
				t.Fatalf("Expected 1 reflection, got %d", len(reflections))
			}
			if reflections[0].Context != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, reflections[0].Context)
			}
		})
	}
}

func TestDetectPartialEncoding(t *testing.T) {
	tests := []struct {
		name              string
		originalCanary    string
		reflectedCanary   string
		expectLessThan    bool
		expectGreaterThan bool
		expectSingleQuote bool
		expectDoubleQuote bool
	}{
		{
			name:              "Only < encoded",
			originalCanary:    "xSs9K7j<>'\"",
			reflectedCanary:   "xSs9K7j&lt;>'\"",
			expectLessThan:    false,
			expectGreaterThan: true,
			expectSingleQuote: true,
			expectDoubleQuote: true,
		},
		{
			name:              "Only > encoded",
			originalCanary:    "xSs9K7j<>'\"",
			reflectedCanary:   "xSs9K7j<&gt;'\"",
			expectLessThan:    true,
			expectGreaterThan: false,
			expectSingleQuote: true,
			expectDoubleQuote: true,
		},
		{
			name:              "Angle brackets encoded, quotes not",
			originalCanary:    "xSs9K7j<>'\"",
			reflectedCanary:   "xSs9K7j&lt;&gt;'\"",
			expectLessThan:    false,
			expectGreaterThan: false,
			expectSingleQuote: true,
			expectDoubleQuote: true,
		},
		{
			name:              "Quotes encoded, angle brackets not",
			originalCanary:    "xSs9K7j<>'\"",
			reflectedCanary:   "xSs9K7j<>&#39;&quot;",
			expectLessThan:    true,
			expectGreaterThan: true,
			expectSingleQuote: false,
			expectDoubleQuote: false,
		},
		{
			name:              "Only double quote encoded",
			originalCanary:    "xSs9K7j<>'\"",
			reflectedCanary:   "xSs9K7j<>'&quot;",
			expectLessThan:    true,
			expectGreaterThan: true,
			expectSingleQuote: true,
			expectDoubleQuote: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chars := detectAvailableCharacters(tt.reflectedCanary, tt.originalCanary)

			if chars.LessThan != tt.expectLessThan {
				t.Errorf("LessThan: expected %v, got %v", tt.expectLessThan, chars.LessThan)
			}
			if chars.GreaterThan != tt.expectGreaterThan {
				t.Errorf("GreaterThan: expected %v, got %v", tt.expectGreaterThan, chars.GreaterThan)
			}
			if chars.SingleQuote != tt.expectSingleQuote {
				t.Errorf("SingleQuote: expected %v, got %v", tt.expectSingleQuote, chars.SingleQuote)
			}
			if chars.DoubleQuote != tt.expectDoubleQuote {
				t.Errorf("DoubleQuote: expected %v, got %v", tt.expectDoubleQuote, chars.DoubleQuote)
			}
		})
	}
}
