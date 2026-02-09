package xss

import (
	"strings"
	"testing"
)

// TestIsHTMLContentType validates Content-Type header classification.
func TestIsHTMLContentType(t *testing.T) {
	tests := []struct {
		name     string
		headers  string
		expected bool
	}{
		{"text/html", "Content-Type: text/html; charset=utf-8\r\n", true},
		{"text/html no charset", "Content-Type: text/html\r\n", true},
		{"xhtml", "Content-Type: application/xhtml+xml\r\n", true},
		{"json rejected", "Content-Type: application/json\r\n", false},
		{"plain text rejected", "Content-Type: text/plain\r\n", false},
		{"no header assumes html", "", true},
		{"xml rejected", "Content-Type: application/xml\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHTMLContentType(tt.headers); got != tt.expected {
				t.Errorf("isHTMLContentType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestHasStrictCSP validates Content-Security-Policy detection.
func TestHasStrictCSP(t *testing.T) {
	tests := []struct {
		name     string
		headers  string
		expected bool
	}{
		{
			name:     "no CSP",
			headers:  "Content-Type: text/html\r\n",
			expected: false,
		},
		{
			name:     "strict script-src",
			headers:  "Content-Security-Policy: script-src 'self'\r\n",
			expected: true,
		},
		{
			name:     "script-src with unsafe-inline",
			headers:  "Content-Security-Policy: script-src 'self' 'unsafe-inline'\r\n",
			expected: false,
		},
		{
			name:     "default-src only",
			headers:  "Content-Security-Policy: default-src 'self'\r\n",
			expected: true,
		},
		{
			name:     "default-src with unsafe-inline",
			headers:  "Content-Security-Policy: default-src 'self' 'unsafe-inline'\r\n",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasStrictCSP(tt.headers); got != tt.expected {
				t.Errorf("hasStrictCSP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDetectQuoting validates attribute value quote detection.
func TestDetectQuoting(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		marker   string
		expected QuoteStyle
	}{
		{"double-quoted", `<input value="nuclei123">`, "nuclei123", QuoteDouble},
		{"single-quoted", `<input value='nuclei123'>`, "nuclei123", QuoteSingle},
		{"unquoted equals", `<input value=nuclei123 >`, "nuclei123", QuoteNone},
		{"double with prefix", `<input value="prefix nuclei123 suffix">`, "nuclei123", QuoteDouble},
		{"single with prefix", `<input value='prefix nuclei123 suffix'>`, "nuclei123", QuoteSingle},
		{"marker at start", `nuclei123`, "nuclei123", QuoteNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectQuoting([]byte(tt.body), []byte(tt.marker)); got != tt.expected {
				t.Errorf("detectQuoting() = %v (%s), want %v (%s)",
					got, got.String(), tt.expected, tt.expected.String())
			}
		})
	}
}

// TestInRCDATA validates RCDATA/raw-text element detection.
func TestInRCDATA(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		marker   string
		expected bool
	}{
		{
			name:     "inside textarea",
			body:     `<textarea>nuclei123</textarea>`,
			marker:   "nuclei123",
			expected: true,
		},
		{
			name:     "inside title",
			body:     `<title>nuclei123</title>`,
			marker:   "nuclei123",
			expected: true,
		},
		{
			name:     "inside noscript",
			body:     `<noscript>nuclei123</noscript>`,
			marker:   "nuclei123",
			expected: true,
		},
		{
			name:     "inside normal div",
			body:     `<div>nuclei123</div>`,
			marker:   "nuclei123",
			expected: false,
		},
		{
			name:     "after closed textarea",
			body:     `<textarea>safe</textarea><div>nuclei123</div>`,
			marker:   "nuclei123",
			expected: false,
		},
		{
			name:     "inside xmp",
			body:     `<xmp>nuclei123</xmp>`,
			marker:   "nuclei123",
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inRCDATA([]byte(tt.body), []byte(tt.marker)); got != tt.expected {
				t.Errorf("inRCDATA() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestQuoteStyleString validates QuoteStyle string representation.
func TestQuoteStyleString(t *testing.T) {
	tests := []struct {
		q        QuoteStyle
		expected string
	}{
		{QuoteNone, "unquoted"},
		{QuoteDouble, "double"},
		{QuoteSingle, "single"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.q.String(); got != tt.expected {
				t.Errorf("QuoteStyle.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestVerifyContext validates the full verification pipeline.
func TestVerifyContext(t *testing.T) {
	htmlHeaders := "Content-Type: text/html; charset=utf-8\r\n"
	jsonHeaders := "Content-Type: application/json\r\n"
	cspHeaders := "Content-Type: text/html\r\nContent-Security-Policy: script-src 'self'\r\n"

	tests := []struct {
		name        string
		body        string
		headers     string
		marker      string
		ctx         ContextType
		wantMatch   bool
		wantContain string
	}{
		{
			name:      "non-html response rejected",
			body:      `{"key":"nuclei123"}`,
			headers:   jsonHeaders,
			marker:    "nuclei123",
			ctx:       ContextAttribute,
			wantMatch: false,
		},
		{
			name:        "script context verified",
			body:        `<script>var x = "nuclei123";</script>`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextScript,
			wantMatch:   true,
			wantContain: "script",
		},
		{
			name:        "script with CSP noted",
			body:        `<script>var x = "nuclei123";</script>`,
			headers:     cspHeaders,
			marker:      "nuclei123",
			ctx:         ContextScript,
			wantMatch:   true,
			wantContain: "csp-present",
		},
		{
			name:        "attribute double-quoted",
			body:        `<input value="nuclei123">`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextAttribute,
			wantMatch:   true,
			wantContain: "double-quoted",
		},
		{
			name:        "attribute single-quoted",
			body:        `<input value='nuclei123'>`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextAttribute,
			wantMatch:   true,
			wantContain: "single-quoted",
		},
		{
			name:        "attribute unquoted",
			body:        `<input value=nuclei123 >`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextAttribute,
			wantMatch:   true,
			wantContain: "unquoted",
		},
		{
			name:        "html in textarea is rcdata",
			body:        `<textarea>nuclei123</textarea>`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextHTML,
			wantMatch:   true,
			wantContain: "rcdata",
		},
		{
			name:        "html in normal div",
			body:        `<div>nuclei123</div>`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextHTML,
			wantMatch:   true,
			wantContain: "html_tag",
		},
		{
			name:        "comment verified",
			body:        `<!-- nuclei123 -->`,
			headers:     htmlHeaders,
			marker:      "nuclei123",
			ctx:         ContextComment,
			wantMatch:   true,
			wantContain: "comment",
		},
		{
			name:      "no content-type assumes html",
			body:      `<div>nuclei123</div>`,
			headers:   "",
			marker:    "nuclei123",
			ctx:       ContextHTML,
			wantMatch: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, detail := VerifyContext(tt.body, tt.headers, tt.marker, tt.ctx)
			if match != tt.wantMatch {
				t.Errorf("VerifyContext() match = %v, want %v", match, tt.wantMatch)
			}
			if tt.wantContain != "" && !strings.Contains(detail, tt.wantContain) {
				t.Errorf("VerifyContext() detail = %q, want containing %q", detail, tt.wantContain)
			}
		})
	}
}
