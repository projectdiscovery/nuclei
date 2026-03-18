package xss

import (
	"testing"
)

func TestAnalyzeContext_JavascriptURI(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected ContextType
	}{
		{
			name:     "javascript: URI in href should be ContextScriptURI",
			body:     `<a href="javascript:nucleiXSScanary</>\"'">click</a>`,
			expected: ContextScriptURI,
		},
		{
			name:     "javascript: URI in src should be ContextScriptURI",
			body:     `<iframe src="javascript:nucleiXSScanary</>\"'"></iframe>`,
			expected: ContextScriptURI,
		},
		{
			name:     "javascript: URI case insensitive",
			body:     `<a href="JAVASCRIPT:nucleiXSScanary</>\"'">click</a>`,
			expected: ContextScriptURI,
		},
		{
			name:     "javascript: URI with spaces",
			body:     `<a href=" javascript:nucleiXSScanary</>\"'">click</a>`,
			expected: ContextScriptURI,
		},
		{
			name:     "regular href is ContextAttribute",
			body:     `<a href="https://example.com/nucleiXSScanary</>\"'">click</a>`,
			expected: ContextAttribute,
		},
		{
			name:     "data: URI is ContextAttribute (not script)",
			body:     `<a href="data:text/html,nucleiXSScanary</>\"'">click</a>`,
			expected: ContextAttribute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeContext(tt.body, XSSCanary)
			if result.Context != tt.expected {
				t.Errorf("expected context %s, got %s", tt.expected, result.Context)
			}
		})
	}
}

func TestAnalyzeContext_JSONScriptBlocks(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected ContextType
	}{
		{
			name:     "application/json script block should be ContextJSONScript",
			body:     `<script type="application/json">{"data":"nucleiXSScanary</>\"'"}</script>`,
			expected: ContextJSONScript,
		},
		{
			name:     "application/ld+json script block should be ContextJSONScript",
			body:     `<script type="application/ld+json">{"@type":"nucleiXSScanary</>\""}</script>`,
			expected: ContextJSONScript,
		},
		{
			name:     "importmap script block should be ContextJSONScript",
			body:     `<script type="importmap">{"imports":{"x":"nucleiXSScanary</>\""}}</script>`,
			expected: ContextJSONScript,
		},
		{
			name:     "regular script block should be ContextScript",
			body:     `<script>var x = "nucleiXSScanary</>\"'";</script>`,
			expected: ContextScript,
		},
		{
			name:     "no type attribute script should be ContextScript",
			body:     `<script>nucleiXSScanary</>\"'</script>`,
			expected: ContextScript,
		},
		{
			name:     "text/javascript script should be ContextScript",
			body:     `<script type="text/javascript">nucleiXSScanary</>\"'</script>`,
			expected: ContextScript,
		},
		{
			name:     "module script should be ContextScript",
			body:     `<script type="module">nucleiXSScanary</>\"'</script>`,
			expected: ContextScript,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeContext(tt.body, XSSCanary)
			if result.Context != tt.expected {
				t.Errorf("expected context %s, got %s", tt.expected, result.Context)
			}
		})
	}
}

func TestAnalyzeContext_CaseInsensitiveReflection(t *testing.T) {
	body := `<div>NUCLEIXSSCANARY</>\"'</div>`
	result := AnalyzeContext(body, XSSCanary)
	if result.Context == ContextNone {
		t.Error("expected reflection to be found with case-insensitive search")
	}
	if result.Context != ContextHTMLText {
		t.Errorf("expected ContextHTMLText, got %s", result.Context)
	}
}

func TestAnalyzeContext_SrcdocAttribute(t *testing.T) {
	body := `<iframe srcdoc="nucleiXSScanary</>\"'"></iframe>`
	result := AnalyzeContext(body, XSSCanary)
	if result.Context != ContextHTMLText {
		t.Errorf("expected ContextHTMLText for srcdoc attribute, got %s", result.Context)
	}
}

func TestAnalyzeContext_BasicContexts(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected ContextType
	}{
		{
			name:     "HTML text context",
			body:     `<div>hello nucleiXSScanary</>\"' world</div>`,
			expected: ContextHTMLText,
		},
		{
			name:     "HTML comment context",
			body:     `<!-- nucleiXSScanary</>\"' -->`,
			expected: ContextHTMLComment,
		},
		{
			name:     "no reflection",
			body:     `<div>hello world</div>`,
			expected: ContextNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeContext(tt.body, XSSCanary)
			if result.Context != tt.expected {
				t.Errorf("expected context %s, got %s", tt.expected, result.Context)
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
		{ContextHTMLText, "html_text"},
		{ContextAttribute, "attribute"},
		{ContextScriptURI, "script_uri"},
		{ContextJSONScript, "json_script"},
	}

	for _, tt := range tests {
		if got := tt.ctx.String(); got != tt.expected {
			t.Errorf("ContextType(%d).String() = %q, want %q", tt.ctx, got, tt.expected)
		}
	}
}

func TestIsJSONScriptType(t *testing.T) {
	tests := []struct {
		scriptType string
		expected   bool
	}{
		{"application/json", true},
		{"application/ld+json", true},
		{"application/json+ld", true},
		{"text/json", true},
		{"importmap", true},
		{"application/geo+json", true},
		{"text/javascript", false},
		{"application/javascript", false},
		{"module", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isJSONScriptType(tt.scriptType); got != tt.expected {
			t.Errorf("isJSONScriptType(%q) = %v, want %v", tt.scriptType, got, tt.expected)
		}
	}
}

func TestIsInsideJSString(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		canary string
		want   bool
	}{
		{
			name:   "inside double quotes",
			text:   `var x = "nucleiXSScanary</>\"'";`,
			canary: XSSCanary,
			want:   true,
		},
		{
			name:   "inside single quotes",
			text:   `var x = 'nucleiXSScanary</>\"'';`,
			canary: XSSCanary,
			want:   true,
		},
		{
			name:   "not inside string",
			text:   `var nucleiXSScanary</>\"' = 42;`,
			canary: XSSCanary,
			want:   false,
		},
		{
			name:   "inside template literal",
			text:   "var x = `nucleiXSScanary</>\"'`;",
			canary: XSSCanary,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInsideJSString(tt.text, tt.canary); got != tt.want {
				t.Errorf("isInsideJSString() = %v, want %v", got, tt.want)
			}
		})
	}
}
