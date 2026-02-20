package xss

import (
	"strings"
	"testing"
)

func TestClassifyContexts(t *testing.T) {
	payload := "PAYLOAD"

	tests := []struct {
		name   string
		body   string
		reason string
	}{
		{
			name:   "html",
			body:   "<html><body>hello PAYLOAD world</body></html>",
			reason: "html context",
		},
		{
			name:   "script",
			body:   "<script>var a='PAYLOAD';</script>",
			reason: "script context",
		},
		{
			name:   "comment",
			body:   "<!-- PAYLOAD -->",
			reason: "html_comment context",
		},
		{
			name:   "attribute",
			body:   "<div data-x='PAYLOAD'>x</div>",
			reason: "html_attribute context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := classifyContexts(tt.body, payload)
			if !ok {
				t.Fatalf("expected match")
			}
			if reason == "" || !strings.Contains(reason, tt.reason) {
				t.Fatalf("expected reason containing %q, got %q", tt.reason, reason)
			}
		})
	}
}
