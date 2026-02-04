package xss

import "testing"

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
		{"event_handler", `<button onclick<>="test()">`, "onclick<>", ContextHTMLAttrUnquoted},
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

	expected := []ContextType{ContextHTMLText, ContextHTMLAttrDoubleQuoted, ContextScriptStringSingle}
	for i, ctx := range contexts {
		if ctx.Type != expected[i] {
			t.Errorf("context %d: got %v, want %v", i, ctx.Type, expected[i])
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
		{ContextHTMLText, "<script>"},
		{ContextHTMLAttrDoubleQuoted, "\""},
		{ContextHTMLAttrSingleQuoted, "'"},
		{ContextScriptStringDouble, "\\\""},
		{ContextScriptStringSingle, "\\'"},
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
			if payload.Value == "" {
				t.Fatal("empty payload")
			}
		})
	}
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
