package xss

import (
	"strings"
	"testing"
)

// TestContextDetection validates context identification across various HTML structures
func TestContextDetection(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		canary   string
		expected ContextType
	}{
		{"html_text", `<div>CANARY</div>`, "CANARY", ContextHTMLText},
		{"attr_double", `<input value="CANARY">`, "CANARY", ContextHTMLAttrDoubleQuoted},
		{"attr_single", `<input value='CANARY'>`, "CANARY", ContextHTMLAttrSingleQuoted},
		{"attr_unquoted", `<input value=CANARY>`, "CANARY", ContextHTMLAttrUnquoted},
		{"script_code", `<script>var x = CANARY;</script>`, "CANARY", ContextScriptCode},
		{"script_string_double", `<script>var x = "CANARY";</script>`, "CANARY", ContextScriptStringDouble},
		{"script_string_single", `<script>var x = 'CANARY';</script>`, "CANARY", ContextScriptStringSingle},
		{"script_template", "<script>var x = `${CANARY}`;</script>", "CANARY", ContextScriptTemplateString},
		{"style_block", `<style>.class { color: CANARY; }</style>`, "CANARY", ContextStyleProperty},
		{"title_rcdata", `<title>probe123<></title>`, "probe123<>", ContextRCDATA},
		{"comment_block", `<!-- probe456<> -->`, "probe456<>", ContextHTMLComment},
		{"event_handler", `<button onclick="test('CANARY')">`, "CANARY", ContextEventHandler},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := DetectContextsRobust(tt.html, tt.canary)
			if len(contexts) == 0 {
				t.Fatalf("no contexts detected")
			}
			if contexts[0].Type != tt.expected {
				t.Errorf("got %v, want %v", contexts[0].Type, tt.expected)
			}
		})
	}
}

// TestMultipleReflections ensures all reflection points are identified
func TestMultipleReflections(t *testing.T) {
	html := `<div>CANARY</div><input value="CANARY"><script>var x = 'CANARY';</script>`
	contexts := DetectContextsRobust(html, "CANARY")

	if len(contexts) != 3 {
		t.Fatalf("got %d contexts, want 3", len(contexts))
	}

	// We check if all expected contexts are present, order may vary based on exploitability rank
	foundMap := make(map[ContextType]bool)
	for _, ctx := range contexts {
		foundMap[ctx.Type] = true
	}

	expected := []ContextType{ContextHTMLText, ContextHTMLAttrDoubleQuoted, ContextScriptStringSingle}
	for _, exp := range expected {
		if !foundMap[exp] {
			t.Errorf("missing expected context %v", exp)
		}
	}
}

// TestFilterDetection validates character filter identification
func TestFilterDetection(t *testing.T) {
	tests := []struct {
		name              string
		probe             string
		html              string
		wantAngleBrackets bool
		wantSingleQuote   bool
		wantDoubleQuote   bool
	}{
		{
			"no_filtering",
			"xSs9K7j<>'\"",
			`<div>xSs9K7j<>'"</div>`,
			true, true, true,
		},
		{
			"angle_brackets_encoded",
			"xSs9K7j<>'\"",
			`<div>xSs9K7j&lt;&gt;'"</div>`,
			false, true, true,
		},
		{
			"quotes_encoded",
			"xSs9K7j<>'\"",
			`<div>xSs9K7j<>&apos;&quot;</div>`,
			true, false, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := DetectContextsRobust(tt.html, tt.probe)
			if len(contexts) == 0 {
				t.Fatal("no contexts detected")
			}

			filter := contexts[0].FilterBypass
			if filter.AngleBracketsAllowed != tt.wantAngleBrackets {
				t.Errorf("AngleBracketsAllowed: got %v, want %v", filter.AngleBracketsAllowed, tt.wantAngleBrackets)
			}
			if filter.SingleQuoteAllowed != tt.wantSingleQuote {
				t.Errorf("SingleQuoteAllowed: got %v, want %v", filter.SingleQuoteAllowed, tt.wantSingleQuote)
			}
			if filter.DoubleQuoteAllowed != tt.wantDoubleQuote {
				t.Errorf("DoubleQuoteAllowed: got %v, want %v", filter.DoubleQuoteAllowed, tt.wantDoubleQuote)
			}
		})
	}
}

// TestPayloadSelection verifies context-appropriate payload generation
func TestPayloadSelection(t *testing.T) {
	tests := []struct {
		context      ContextType
		wantContains string
	}{
		{ContextHTMLText, "<img"}, // First payload is <img src=x onerror=
		{ContextHTMLAttrDoubleQuoted, "\""},
		{ContextHTMLAttrSingleQuoted, "'"},
		{ContextScriptStringDouble, "\";"}, // Payload is \";alert([RANDNUM])//
		{ContextScriptStringSingle, "';"},  // Payload is ';alert([RANDNUM])//,
	}

	for _, tt := range tests {
		t.Run(tt.context.String(), func(t *testing.T) {
			reflectionCtx := ReflectionContext{
				Type: tt.context,
				FilterBypass: FilterBypassInfo{
					AngleBracketsAllowed: true,
					SingleQuoteAllowed:   true,
					DoubleQuoteAllowed:   true,
					IsExploitable:        true,
				},
			}

			payload := SelectPayload(reflectionCtx)
			if payload == nil || payload.Value == "" {
				t.Fatal("empty payload")
			}
			// Verify payload contains expected character/pattern
			if !strings.Contains(payload.Value, tt.wantContains) {
				t.Errorf("payload %q does not contain expected %q", payload.Value, tt.wantContains)
			}
		})
	}

	// Test fallback when filters block preferred payload
	t.Run("fallback_on_filter", func(t *testing.T) {
		ctx := ReflectionContext{
			Type: ContextHTMLAttrDoubleQuoted,
			FilterBypass: FilterBypassInfo{
				AngleBracketsAllowed: false, // <script> blocked
				SingleQuoteAllowed:   true,
				DoubleQuoteAllowed:   true,
				IsExploitable:        true,
			},
		}

		payload := SelectPayload(ctx)
		if payload == nil {
			t.Fatal("empty payload")
		}
		// Should choose payload without angle brackets (e.g. onfocus)
		if strings.Contains(payload.Value, "<script>") {
			t.Errorf("selected payload with angle brackets despite filter: %s", payload.Value)
		}
		if !strings.Contains(payload.Value, "onfocus=") {
			t.Errorf("expected onfocus payload, got: %s", payload.Value)
		}
	})
}

// TestEdgeCases validates handling of uncommon HTML structures
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		canary       string
		wantContexts int
	}{
		{"uppercase_tags", "<SCRIPT>var x = CANARY;</SCRIPT>", "CANARY", 1},
		{"nested_quotes", `<div title="x'CANARY'x">`, "CANARY", 1},
		{"svg_script", "<svg><script>CANARY</script></svg>", "CANARY", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := DetectContextsRobust(tt.html, tt.canary)
			if len(contexts) != tt.wantContexts {
				t.Errorf("got %d contexts, want %d", len(contexts), tt.wantContexts)
			}
		})
	}
}

// TestJSONContext validates detection of JSON data in script tags
func TestJSONContext(t *testing.T) {
	html := `<script type="application/json">{"key": "CANARY"}</script>`
	contexts := DetectContextsRobust(html, "CANARY")

	if len(contexts) == 0 {
		t.Fatal("no contexts detected")
	}

	if contexts[0].Type != ContextScriptJSON {
		t.Errorf("got %v, want ContextScriptJSON", contexts[0].Type)
	}
}

// TestCaseInsensitivity ensures tag names are handled case-insensitively
func TestCaseInsensitivity(t *testing.T) {
	tests := []string{
		"<SCRIPT>CANARY</SCRIPT>",
		"<Script>CANARY</Script>",
		"<STYLE>CANARY</STYLE>",
		"<TEXTAREA>CANARY</TEXTAREA>",
	}

	for _, html := range tests {
		contexts := DetectContextsRobust(html, "CANARY")
		if len(contexts) == 0 {
			t.Errorf("no contexts for %s", html)
		}
	}
}

// TestFailFast validates that unexploitable contexts are filtered
func TestFailFast(t *testing.T) {
	// No special characters reflected
	html := `<div>CANARY</div>`
	contexts := DetectContextsRobust(html, "CANARY")

	if len(contexts) == 0 {
		t.Fatal("expected context detection")
	}

	// Should be exploitable (HTML text with no filtering)
	if !contexts[0].FilterBypass.IsExploitable {
		t.Error("HTML text without filters should be exploitable")
	}
}

// TestQuoteDetection validates accurate quote character identification
func TestQuoteDetection(t *testing.T) {
	tests := []struct {
		html      string
		wantQuote rune
	}{
		{`<input value="CANARY">`, '"'},
		{`<input value='CANARY'>`, '\''},
		{`<input value=CANARY>`, 0},
	}

	for _, tt := range tests {
		contexts := DetectContextsRobust(tt.html, "CANARY")
		if len(contexts) == 0 {
			t.Fatal("no contexts detected")
		}
		if contexts[0].QuoteChar != tt.wantQuote {
			t.Errorf("got quote %q, want %q", contexts[0].QuoteChar, tt.wantQuote)
		}
	}
}

// TestRobustnessEdges covers critical edge cases and regression scenarios
// including escaped quote handling, filter detection with trailing HTML, and nested contexts.
func TestRobustnessEdges(t *testing.T) {
	// 1. JS Escaped Quote Handling (Regression)
	t.Run("escaped_quote_handling", func(t *testing.T) {
		// Scenario: Payload is inside a single-quoted string, but contains an escaped quote
		// var x = 'escaped\'...';
		// Logic should track escape state and know we are still inside the single quote string

		input := "var x = 'escaped\\'"
		// Offset is at end of string. Expected: ContextScriptStringSingle
		ctx := analyzeJSContext(input, len(input))
		if ctx != ContextScriptStringSingle {
			t.Errorf("Expected ContextScriptStringSingle, got %v", ctx)
		}
	})

	// 2. Filter Detection with Trailing HTML (Regression)
	t.Run("filter_trailing_html", func(t *testing.T) {
		smartCanary := "Nucl3iXY<>'"
		baseCanary := "Nucl3iXY"

		// HTML Encoded reflection followed by a structural tag that actually contains <
		body := "<div>Nucl3iXY&lt;&gt;&apos;</div>"
		canaryPos := strings.Index(body, baseCanary)

		info := detectFilters(body, canaryPos, smartCanary)

		if info.AngleBracketsAllowed {
			t.Error("False Positive: Angle brackets marked allowed despite being encoded, likely due to trailing </div>")
		}

		if info.SingleQuoteAllowed {
			t.Error("False Positive: Single quote marked allowed despite being encoded")
		}
	})

	// 3. Filter Detection with Allowed HTML (Control)
	t.Run("filter_allowed_control", func(t *testing.T) {
		smartCanary := "Nucl3iXY<>'"
		baseCanary := "Nucl3iXY"
		body := "<div>Nucl3iXY<>'</div>"
		canaryPos := strings.Index(body, baseCanary)

		info := detectFilters(body, canaryPos, smartCanary)

		if !info.AngleBracketsAllowed {
			t.Error("False Negative: Angle brackets marked blocked but are present")
		}
	})

	// 4. Extreme Context: Nested JS in HTML Attribute
	t.Run("nested_js_in_html_attribute", func(t *testing.T) {
		// <div onclick="var x = 'Nucl3iXY'">
		// Tokenizer sees attribute value "var x = 'Nucl3iXY'"
		// detectContextFromToken logic for attribute should detect it is an attribute

		smartCanary := "Nucl3iXY"
		body := `<div onclick="var x = 'Nucl3iXY'">`

		// This uses DetectContextsRobust which calls the tokenizer loop
		contexts := DetectContextsRobust(body, smartCanary)
		if len(contexts) == 0 {
			t.Fatal("Failed to detect context in nested JS attribute")
		}

		// Should be identified as EventHandler because it's in the onclick="..." attribute
		if contexts[0].Type != ContextEventHandler {
			t.Errorf("Expected ContextEventHandler, got %s", contexts[0].Type)
		}
	})

	// 5. Extreme Context: Complex Script with multiple quotes and escapes
	t.Run("complex_script_structure", func(t *testing.T) {
		// var a = "foo\"bar"; var b = 'baz\'qux' + `Nucl3iXY`;
		smartCanary := "Nucl3iXY"
		body := `var a = "foo\"bar"; var b = 'baz\'qux' + ` + "`" + smartCanary + "`" + `;`
		canaryPos := strings.Index(body, smartCanary)

		// We test analyzeJSContext specifically
		ctx := analyzeJSContext(body, canaryPos)
		if ctx != ContextScriptTemplateString {
			t.Errorf("Expected ContextScriptTemplateString, got %s", ctx)
		}
	})

	// 6. Test Trailing Malformed Content (CodeRabbit identifying blind spot)
	t.Run("trailing_malformed_html", func(t *testing.T) {
		html := `<div>Valid</div><a href="` // Truncated/Malformed
		canary := "Nucl3iXY<>'"
		body := html + canary
		contexts := DetectContextsRobust(body, canary)
		if len(contexts) == 0 {
			t.Fatal("no contexts detected for trailing malformed content")
		}
		if contexts[0].Type != ContextHTMLText {
			t.Errorf("expected ContextHTMLText fallback, got %v", contexts[0].Type)
		}
		// Verify filter detection ran
		if !contexts[0].FilterBypass.IsExploitable {
			t.Error("expected IsExploitable to be true for unencoded canary in malformed context")
		}
	})
}
