package xss

import (
	"testing"
)

func TestContextClassificationJavaScriptURI(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		payload  string
		expected ContextType
	}{
		{
			name:     "javascript URI in href",
			html:     `<a href="javascript:alert(nucleiXSScanary)">`,
			payload:  "nucleiXSScanary",
			expected: ContextScript,
		},
		{
			name:     "javascript URI in onclick",
			html:     `<div onclick="javascript:alert(nucleiXSScanary)"></div>`,
			payload:  "nucleiXSScanary",
			expected: ContextScript,
		},
		{
			name:     "javascript URI with spaces",
			html:     `<a href="javascript : alert(nucleiXSScanary)">`,
			payload:  "nucleiXSScanary",
			expected: ContextScript,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyContext(tt.html, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

func TestContextClassificationJSONScript(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		payload  string
		expected ContextType
	}{
		{
			name:     "JSON script block",
			html:     `<script type="application/json">{"payload":"nucleiXSScanary"}</script>`,
			payload:  "nucleiXSScanary",
			expected: ContextJSON,
		},
		{
			name:     "JSON script with spaces in type",
			html:     `<script type = "application/json" >{"payload":"nucleiXSScanary"}</script>`,
			payload:  "nucleiXSScanary",
			expected: ContextJSON,
		},
		{
			name:     "JSON script with single quotes",
			html:     `<script type='application/json'>["nucleiXSScanary"]</script>`,
			payload:  "nucleiXSScanary",
			expected: ContextJSON,
		},
		{
			name:     "Regular script block with payload",
			html:     `<script>alert("nucleiXSScanary")</script>`,
			payload:  "nucleiXSScanary",
			expected: ContextScript,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyContext(tt.html, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

func TestContextClassificationSrcdoc(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		payload  string
		expected ContextType
	}{
		{
			name:     "srcdoc attribute with HTML",
			html:     `<iframe srcdoc="<img src=x onerror='nucleiXSScanary'>"></iframe>`,
			payload:  "nucleiXSScanary",
			expected: ContextHTMLInjection,
		},
		{
			name:     "srcdoc with payload in script",
			html:     `<iframe srcdoc="<script>alert('nucleiXSScanary')</script>"></iframe>`,
			payload:  "nucleiXSScanary",
			expected: ContextHTMLInjection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyContext(tt.html, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

func TestContextClassificationCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		payload  string
		expected ContextType
	}{
		{
			name:     "Case insensitive script tag",
			html:     `<SCRIPT>alert('nucleiXSScanary')</SCRIPT>`,
			payload:  "nucleiXSScanary",
			expected: ContextScript,
		},
		{
			name:     "Case insensitive JSON script",
			html:     `<SCRIPT TYPE="APPLICATION/JSON">{"data":"nucleiXSScanary"}</SCRIPT>`,
			payload:  "nucleiXSScanary",
			expected: ContextJSON,
		},
		{
			name:     "Case insensitive payload reflection",
			html:     `<p>Data: NucleiXSScanary</p>`,
			payload:  "nucleiXSScanary",
			expected: ContextHTML,
		},
		{
			name:     "Case insensitive javascript URI",
			html:     `<a href="JAVASCRIPT:void(nucleiXSScanary)">`,
			payload:  "nucleiXSScanary",
			expected: ContextScript,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyContext(tt.html, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

func TestContextClassificationAttribute(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		payload  string
		expected ContextType
	}{
		{
			name:     "Payload in href attribute",
			html:     `<a href="http://example.com?q=nucleiXSScanary">`,
			payload:  "nucleiXSScanary",
			expected: ContextAttribute,
		},
		{
			name:     "Payload in data attribute",
			html:     `<div data-value="nucleiXSScanary"></div>`,
			payload:  "nucleiXSScanary",
			expected: ContextAttribute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyContext(tt.html, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

func TestContextClassificationHTMLContent(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		payload  string
		expected ContextType
	}{
		{
			name:     "Payload in HTML content",
			html:     `<p>Data: nucleiXSScanary</p>`,
			payload:  "nucleiXSScanary",
			expected: ContextHTML,
		},
		{
			name:     "Payload in div content",
			html:     `<div>nucleiXSScanary</div>`,
			payload:  "nucleiXSScanary",
			expected: ContextHTML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyContext(tt.html, tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

// FIX: Add edge case tests as requested in review comments

func TestContextClassification_EmptyPayload(t *testing.T) {
	html := `<p>Data: test</p>`
	result := ClassifyContext(html, "")
	if result != ContextHTML {
		t.Errorf("Expected ContextHTML for empty payload, got %s", result.String())
	}
}

func TestContextClassification_MultipleReflections(t *testing.T) {
	// Test that the most dangerous context is returned when payload appears multiple times
	html := `<script type="application/json">{"data":"nucleiXSScanary"}</script><script>alert('nucleiXSScanary')</script>`
	result := ClassifyContext(html, "nucleiXSScanary")
	// Should return ContextScript (more dangerous) not ContextJSON
	if result != ContextScript {
		t.Errorf("Expected ContextScript for multiple reflections, got %s", result.String())
	}
}

func TestContextClassification_JSONAndScriptBlocks(t *testing.T) {
	// Test proper handling of JSON + script blocks
	html := `<script type="application/json">{"x":"nucleiXSScanary"}</script><script>var y="nucleiXSScanary"</script>`
	result := ClassifyContext(html, "nucleiXSScanary")
	// Should return ContextScript (executable) not ContextJSON
	if result != ContextScript {
		t.Errorf("Expected ContextScript, got %s", result.String())
	}
}

func TestContextClassification_NestedIframeSrcdoc(t *testing.T) {
	// Test nested iframe with srcdoc
	html := `<iframe srcdoc="<iframe srcdoc='<script>nucleiXSScanary</script>'></iframe>"></iframe>`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextHTMLInjection {
		t.Errorf("Expected ContextHTMLInjection for nested srcdoc, got %s", result.String())
	}
}

func TestContextClassification_EscapedQuotes(t *testing.T) {
	// Test attribute detection with escaped quotes
	html := `<div data-value="test\"nucleiXSScanary\">`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextAttribute {
		t.Errorf("Expected ContextAttribute with escaped quotes, got %s", result.String())
	}
}

func TestContextClassification_ScriptInString(t *testing.T) {
	// Test payload in script string literal
	html := `<script>var x = "nucleiXSScanary";</script>`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextScript {
		t.Errorf("Expected ContextScript for script content, got %s", result.String())
	}
}

func TestContextClassification_JavaScriptURIFalsePositive(t *testing.T) {
	// Test that javascript: in text content doesn't cause false positive
	html := `<p>Learn about javascript: protocol</p><input value="nucleiXSScanary">`
	result := ClassifyContext(html, "nucleiXSScanary")
	// Should be ContextAttribute, not ContextScript
	if result != ContextAttribute {
		t.Errorf("Expected ContextAttribute, got %s (false positive for javascript: URI)", result.String())
	}
}

func TestContextClassification_JavaScriptURIFalseNegative(t *testing.T) {
	// Test that javascript: URI is detected even with padding
	html := `<a href="javascript:/* padding padding padding padding padding padding padding */alert(nucleiXSScanary)">`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextScript {
		t.Errorf("Expected ContextScript for javascript: URI with padding, got %s", result.String())
	}
}

func TestContextClassification_MultipleScriptBlocks(t *testing.T) {
	// Test proper handling of multiple script blocks
	html := `<script>var x = 1;</script><p>nucleiXSScanary</p><script>var y = 2;</script>`
	result := ClassifyContext(html, "nucleiXSScanary")
	// Payload is in HTML text between script blocks, not in script
	if result != ContextHTML {
		t.Errorf("Expected ContextHTML for payload between script blocks, got %s", result.String())
	}
}

func TestContextClassification_ScriptWithStringClosing(t *testing.T) {
	// Test script with </script> in string literal
	html := `<script>var x = '</script>';</script><p>nucleiXSScanary</p>`
	result := ClassifyContext(html, "nucleiXSScanary")
	// Payload is in HTML text after the actual script block
	if result != ContextHTML {
		t.Errorf("Expected ContextHTML, got %s", result.String())
	}
}

func TestContextClassification_AttributeWithEscapedQuotes(t *testing.T) {
	// Test attribute detection with escaped quotes
	html := `<input value="test\"nucleiXSScanary\"end">`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextAttribute {
		t.Errorf("Expected ContextAttribute with escaped quotes, got %s", result.String())
	}
}

func TestContextClassification_SrcdocInTextContent(t *testing.T) {
	// Test that srcdoc in text content doesn't cause false positive
	html := `<p>The srcdoc attribute allows HTML</p><div>nucleiXSScanary</div>`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextHTML {
		t.Errorf("Expected ContextHTML, got %s (false positive for srcdoc)", result.String())
	}
}

func TestContextContextType_Priority(t *testing.T) {
	// Test that priority ordering is correct
	if ContextScript.priority() <= ContextHTMLInjection.priority() {
		t.Error("ContextScript should have higher priority than ContextHTMLInjection")
	}
	if ContextHTMLInjection.priority() <= ContextAttribute.priority() {
		t.Error("ContextHTMLInjection should have higher priority than ContextAttribute")
	}
	if ContextAttribute.priority() <= ContextHTML.priority() {
		t.Error("ContextAttribute should have higher priority than ContextHTML")
	}
	if ContextHTML.priority() <= ContextJSON.priority() {
		t.Error("ContextHTML should have higher priority than ContextJSON")
	}
}

func TestContextClassification_NoReflection(t *testing.T) {
	html := `<p>Data: test</p>`
	result := ClassifyContext(html, "nucleiXSScanary")
	if result != ContextHTML {
		t.Errorf("Expected ContextHTML for no reflection, got %s", result.String())
	}
}
