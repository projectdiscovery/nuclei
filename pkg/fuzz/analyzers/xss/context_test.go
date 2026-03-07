package xss

import (
	"testing"
)

func TestAnalyzeContext(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		reflection string
		expected  Context
		expectedAttr string
	}{
		{
			name:      "javascript URI in href attribute",
			html:      `<a href="javascript:alert(nucleiXSScanary)">click</a>`,
			reflection: "nucleiXSScanary",
			expected:  ContextScript,
			expectedAttr: "href",
		},
		{
			name:      "javascript URI with different case",
			html:      `<a href="JAVASCRIPT:alert(nucleiXSScanary)">click</a>`,
			reflection: "nucleiXSScanary",
			expected:  ContextScript,
			expectedAttr: "href",
		},
		{
			name:      "application/json script block",
			html:      `<script type="application/json">nucleiXSScanary</script>`,
			reflection: "nucleiXSScanary",
			expected:  ContextText,
			expectedAttr: "",
		},
		{
			name:      "text/json script block",
			html:      `<script type="text/json">nucleiXSScanary</script>`,
			reflection: "nucleiXSScanary",
			expected:  ContextText,
			expectedAttr: "",
		},
		{
			name:      "executable script block",
			html:      `<script>nucleiXSScanary</script>`,
			reflection: "nucleiXSScanary",
			expected:  ContextScript,
			expectedAttr: "",
		},
		{
			name:      "srcdoc attribute",
			html:      `<iframe srcdoc="<p>nucleiXSScanary</p>"></iframe>`,
			reflection: "nucleiXSScanary",
			expected:  ContextHTML,
			expectedAttr: "srcdoc",
		},
		{
			name:      "case-insensitive reflection detection",
			html:      `<div>NUCLEXSSCANARY</div>`,
			reflection: "nucleiXSScanary",
			expected:  ContextText,
			expectedAttr: "",
		},
		{
			name:      "regular attribute",
			html:      `<input value="nucleiXSScanary">`,
			reflection: "nucleiXSScanary",
			expected:  ContextAttribute,
			expectedAttr: "value",
		},
		{
			name:      "event handler attribute",
			html:      `<button onclick="alert('nucleiXSScanary')">click</button>`,
			reflection: "nucleiXSScanary",
			expected:  ContextScript,
			expectedAttr: "onclick",
		},
		{
			name:      "application/ld+json script block",
			html:      `<script type="application/ld+json">nucleiXSScanary</script>`,
			reflection: "nucleiXSScanary",
			expected:  ContextText,
			expectedAttr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context, attr, err := AnalyzeContext(tt.reflection, []byte(tt.html))
			if err != nil {
				t.Fatalf("AnalyzeContext() error = %v", err)
			}
			if context != tt.expected {
				t.Errorf("AnalyzeContext() context = %v, expected %v", context, tt.expected)
			}
			if attr != tt.expectedAttr {
				t.Errorf("AnalyzeContext() attribute = %v, expected %v", attr, tt.expectedAttr)
			}
		})
	}
}

func TestIsReflected(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		reflection string
		expected   bool
	}{
		{
			name:       "case-insensitive reflection",
			body:       []byte(`<div>NUCLEXSSCANARY</div>`),
			reflection: "nucleiXSScanary",
			expected:   true,
		},
		{
			name:       "exact match",
			body:       []byte(`<div>nucleiXSScanary</div>`),
			reflection: "nucleiXSScanary",
			expected:   true,
		},
		{
			name:       "no reflection",
			body:       []byte(`<div>other</div>`),
			reflection: "nucleiXSScanary",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsReflected(tt.reflection, tt.body); got != tt.expected {
				t.Errorf("IsReflected() = %v, expected %v", got, tt.expected)
			}
		})
	}
}
