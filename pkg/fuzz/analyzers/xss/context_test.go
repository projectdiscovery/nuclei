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
			html:     `<p>Data: NucleiXSSCanary</p>`,
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
