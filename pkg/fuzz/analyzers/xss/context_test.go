package xss

import (
	"testing"
)

func TestJavascriptURIClassifiedAsScript(t *testing.T) {
	// FIX #1: javascript: URIs should be ContextScript, not ContextAttribute
	body := `<a href="javascript:alert(MARKER)">click</a>`
	refs := DetectReflections(body, "MARKER")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	found := false
	for _, r := range refs {
		if r.AttrName == "href" {
			if r.Context != ContextScript {
				t.Errorf("javascript: URI: got context %v, want ContextScript", r.Context)
			}
			found = true
		}
	}
	if !found {
		t.Error("no reflection found for href attribute")
	}
}

func TestNonExecutableScriptType(t *testing.T) {
	// FIX #2: <script type="application/json"> should NOT be treated as executable
	body := `<script type="application/json">{"key": "MARKER"}</script>`
	refs := DetectReflections(body, "MARKER")
	for _, r := range refs {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Errorf("application/json script block: got context %v, want non-script context", r.Context)
		}
	}
}

func TestExecutableScriptType(t *testing.T) {
	// Regular script tags should still be ContextScript
	body := `<script>var x = "MARKER";</script>`
	refs := DetectReflections(body, "MARKER")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection in executable script")
	}
	found := false
	for _, r := range refs {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			found = true
		}
	}
	if !found {
		t.Error("executable script not classified as script context")
	}
}

func TestCaseInsensitiveReflectionDetection(t *testing.T) {
	// FIX #3: Reflection detection should be case-insensitive
	body := `<div>MARKER</div>`
	refs := DetectReflections(body, "marker") // lowercase marker, uppercase in body
	if len(refs) == 0 {
		t.Error("case-insensitive detection failed: expected reflection for case-mismatched marker")
	}
}

func TestSrcdocClassifiedAsHTMLInjection(t *testing.T) {
	// FIX #4: srcdoc should be treated as HTML injection context
	body := `<iframe srcdoc="<img src=x onerror=alert(MARKER)>"></iframe>`
	refs := DetectReflections(body, "MARKER")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection in srcdoc")
	}
	found := false
	for _, r := range refs {
		if r.AttrName == "srcdoc" {
			if r.Context != ContextHTMLText {
				t.Errorf("srcdoc attr: got context %v, want ContextHTMLText (HTML injection)", r.Context)
			}
			found = true
		}
	}
	if !found {
		t.Error("no reflection found for srcdoc attribute")
	}
}

func TestEventHandlerClassifiedAsScript(t *testing.T) {
	body := `<img onerror="alert(MARKER)" src="x">`
	refs := DetectReflections(body, "MARKER")
	found := false
	for _, r := range refs {
		if r.AttrName == "onerror" {
			if r.Context != ContextScript {
				t.Errorf("event handler: got context %v, want ContextScript", r.Context)
			}
			found = true
		}
	}
	if !found {
		t.Error("no reflection found for onerror attribute")
	}
}

func TestNormalAttributeContext(t *testing.T) {
	body := `<input value="MARKER" type="text">`
	refs := DetectReflections(body, "MARKER")
	if len(refs) == 0 {
		t.Fatal("expected reflection in attribute")
	}
	for _, r := range refs {
		if r.AttrName == "value" && r.Context != ContextAttribute {
			t.Errorf("normal attr: got context %v, want ContextAttribute", r.Context)
		}
	}
}

func TestHTMLCommentContext(t *testing.T) {
	body := `<!-- MARKER is here --><p>text</p>`
	refs := DetectReflections(body, "MARKER")
	found := false
	for _, r := range refs {
		if r.Context == ContextHTMLComment {
			found = true
		}
	}
	if !found {
		t.Error("comment reflection not detected")
	}
}

func TestIsExecutableScriptType(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"text/javascript", true},
		{"application/javascript", true},
		{"application/json", false},
		{"application/ld+json", false},
		{"text/template", false},
		{"APPLICATION/JSON", false},
		{"application/json; charset=utf-8", false},
	}
	for _, tt := range tests {
		got := isExecutableScriptType(tt.input)
		if got != tt.want {
			t.Errorf("isExecutableScriptType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsJavascriptURI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"javascript:alert(1)", true},
		{"JAVASCRIPT:alert(1)", true},
		{"  javascript:void(0)", true},
		{"https://example.com", false},
		{"data:text/html,<h1>hi</h1>", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isJavascriptURI(tt.input)
		if got != tt.want {
			t.Errorf("isJavascriptURI(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsHTMLInjectionAttr(t *testing.T) {
	if !isHTMLInjectionAttr("srcdoc") {
		t.Error("srcdoc should be HTML injection attr")
	}
	if !isHTMLInjectionAttr("SRCDOC") {
		t.Error("SRCDOC (uppercase) should be HTML injection attr")
	}
	if isHTMLInjectionAttr("href") {
		t.Error("href should not be HTML injection attr")
	}
}
