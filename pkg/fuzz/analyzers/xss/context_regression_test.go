package xss

import (
	"testing"
)

// TestJavaScriptURIDetection tests FIX #1: javascript: URIs should be ContextScript
func TestJavaScriptURIDetection(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected Context
	}{
		{
			name:     "javascript URI in href",
			html:     `<a href="javascript:alert(1)">click</a>`,
			expected: ContextScript,
		},
		{
			name:     "javascript URI with spaces",
			html:     `<a href="  javascript:alert(1)">click</a>`,
			expected: ContextScript,
		},
		{
			name:     "javascript URI uppercase",
			html:     `<a href="JAVASCRIPT:alert(1)">click</a>`,
			expected: ContextScript,
		},
		{
			name:     "javascript URI mixed case",
			html:     `<a href="JaVaScRiPt:alert(1)">click</a>`,
			expected: ContextScript,
		},
		{
			name:     "normal http URL",
			html:     `<a href="http://example.com">click</a>`,
			expected: ContextAttribute,
		},
		{
			name:     "normal https URL",
			html:     `<a href="https://example.com">click</a>`,
			expected: ContextAttribute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflections := DetectReflections(tt.html, "nucleiXSScanary")
			// Add marker to test
			testHTML := tt.html
			if tt.name == "javascript URI in href" {
				testHTML = `<a href="javascript:alert(nucleiXSScanary)">click</a>`
			} else if tt.name == "javascript URI with spaces" {
				testHTML = `<a href="  javascript:alert(nucleiXSScanary)">click</a>`
			} else if tt.name == "javascript URI uppercase" {
				testHTML = `<a href="JAVASCRIPT:alert(nucleiXSScanary)">click</a>`
			} else if tt.name == "javascript URI mixed case" {
				testHTML = `<a href="JaVaScRiPt:alert(nucleiXSScanary)">click</a>`
			} else if tt.name == "normal http URL" {
				testHTML = `<a href="http://example.com?x=nucleiXSScanary">click</a>`
			} else if tt.name == "normal https URL" {
				testHTML = `<a href="https://example.com?x=nucleiXSScanary">click</a>`
			}

			reflections = DetectReflections(testHTML, "nucleiXSScanary")
			if len(reflections) == 0 {
				t.Fatalf("expected reflection, got none")
			}
			if reflections[0].Context != tt.expected {
				t.Errorf("expected context %v, got %v", tt.expected, reflections[0].Context)
			}
		})
	}
}

// TestScriptTypeApplicationJSON tests FIX #2: application/json should not be ContextScript
func TestScriptTypeApplicationJSON(t *testing.T) {
	html := `<script type="application/json">{"x": "nucleiXSScanary"}</script>`
	reflections := DetectReflections(html, "nucleiXSScanary")

	if len(reflections) == 0 {
		t.Fatalf("expected reflection, got none")
	}

	// application/json should NOT be treated as executable script
	// It should be treated as HTML text or none
	if reflections[0].Context == ContextScript {
		t.Errorf("application/json should not be treated as ContextScript, got %v", reflections[0].Context)
	}
}

// TestScriptTypeLdJSON tests FIX #2: application/ld+json should not be ContextScript
func TestScriptTypeLdJSON(t *testing.T) {
	html := `<script type="application/ld+json">{"@context": "nucleiXSScanary"}</script>`
	reflections := DetectReflections(html, "nucleiXSScanary")

	if len(reflections) == 0 {
		t.Fatalf("expected reflection, got none")
	}

	if reflections[0].Context == ContextScript {
		t.Errorf("application/ld+json should not be treated as ContextScript, got %v", reflections[0].Context)
	}
}

// TestNormalScriptStillWorks tests that normal scripts are still detected as ContextScript
func TestNormalScriptStillWorks(t *testing.T) {
	html := `<script>var x = "nucleiXSScanary";</script>`
	reflections := DetectReflections(html, "nucleiXSScanary")

	if len(reflections) == 0 {
		t.Fatalf("expected reflection, got none")
	}

	if reflections[0].Context != ContextScriptString {
		t.Errorf("normal script should be ContextScriptString, got %v", reflections[0].Context)
	}
}

// TestSrcdocAttribute tests FIX #4: srcdoc should be ContextHTMLText
func TestSrcdocAttribute(t *testing.T) {
	html := `<iframe srcdoc="<html>nucleiXSScanary</html>"></iframe>`
	reflections := DetectReflections(html, "nucleiXSScanary")

	if len(reflections) == 0 {
		t.Fatalf("expected reflection, got none")
	}

	// srcdoc should be treated as HTML injection context (HTMLText)
	if reflections[0].Context != ContextHTMLText {
		t.Errorf("srcdoc should be ContextHTMLText, got %v", reflections[0].Context)
	}
}

// TestCaseInsensitiveReflection tests FIX #3: reflection detection should be case-insensitive
func TestCaseInsensitiveReflection(t *testing.T) {
	// Marker with mixed case should still be found
	html := `<div>NUCLEIXSSCANARY</div>`
	reflections := DetectReflections(html, "nucleiXSScanary")

	if len(reflections) == 0 {
		t.Errorf("case-insensitive reflection should be detected")
	}

	// Marker in attribute with different case
	html2 := `<a href="http://example.com?X=NUCLEIXSSCANARY">test</a>`
	reflections2 := DetectReflections(html2, "nucleiXSScanary")

	if len(reflections2) == 0 {
		t.Errorf("case-insensitive attribute reflection should be detected")
	}
}

// TestAllFixesTogether tests all fixes working together
func TestAllFixesTogether(t *testing.T) {
	html := `
		<a href="javascript:alert(nucleiXSScanary)">js uri</a>
		<script type="application/json">{"x": "nucleiXSScanary"}</script>
		<iframe srcdoc="<div>nucleiXSScanary</div>"></iframe>
		<DIV>NUCLEIXSSCANARY</DIV>
	`

	reflections := DetectReflections(html, "nucleiXSScanary")

	if len(reflections) < 4 {
		t.Errorf("expected at least 4 reflections, got %d", len(reflections))
	}

	// Verify each fix
	hasScriptContext := false
	hasNonScriptJSON := false
	hasHTMLText := false

	for _, r := range reflections {
		if r.Context == ContextScript {
			hasScriptContext = true
		}
		if r.TagName == "script" && r.Context != ContextScript {
			hasNonScriptJSON = true
		}
		if r.Context == ContextHTMLText {
			hasHTMLText = true
		}
	}

	if !hasScriptContext {
		t.Error("should detect javascript: URI as ContextScript")
	}
	if !hasNonScriptJSON {
		t.Error("should not treat application/json as ContextScript")
	}
	if !hasHTMLText {
		t.Error("should detect HTML text contexts")
	}
}
