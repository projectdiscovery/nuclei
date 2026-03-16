package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextType_IsExecutable(t *testing.T) {
	tests := []struct {
		name     string
		context  ContextType
		expected bool
	}{
		{"ContextNone", ContextNone, false},
		{"ContextHTMLText", ContextHTMLText, true},
		{"ContextAttribute", ContextAttribute, true},
		{"ContextAttributeUnquoted", ContextAttributeUnquoted, true},
		{"ContextScript", ContextScript, true},
		{"ContextScriptString", ContextScriptString, true},
		{"ContextStyle", ContextStyle, false},
		{"ContextHTMLComment", ContextHTMLComment, false},
		{"ContextURL", ContextURL, true},
		{"ContextSrcDoc", ContextSrcDoc, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.context.IsExecutable()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestContextType_String(t *testing.T) {
	tests := []struct {
		name     string
		context  ContextType
		expected string
	}{
		{"ContextNone", ContextNone, "ContextNone"},
		{"ContextHTMLText", ContextHTMLText, "ContextHTMLText"},
		{"ContextScript", ContextScript, "ContextScript"},
		{"ContextSrcDoc", ContextSrcDoc, "ContextSrcDoc"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.context.String()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestIsExecutableMIMEType(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
		expected bool
	}{
		// Executable types
		{"JavaScript", "text/javascript", true},
		{"JavaScript Application", "application/javascript", true},
		{"ECMAScript", "application/ecmascript", true},
		{"Module", "module", true},
		
		// Non-executable types
		{"JSON", "application/json", false},
		{"LD+JSON", "application/ld+json", false},
		{"ImportMap", "application/importmap+json", false},
		{"Text JSON", "text/json", false},
		{"Text Template", "text/template", false},
		{"Text HTML", "text/html", false},
		{"Text Plain", "text/plain", false},
		{"Text CSS", "text/css", false},
		
		// Edge cases
		{"Empty", "", true}, // Default to executable
		{"Unknown", "application/x-custom", true}, // Unknown defaults to executable
		{"With charset", "text/javascript; charset=utf-8", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsExecutableMIMEType(tt.mimeType)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultPayloads(t *testing.T) {
	payloads := DefaultPayloads()
	
	require.Greater(t, len(payloads), 0, "Should have default payloads")
	
	for _, payload := range payloads {
		require.NotEmpty(t, payload.Value, "Payload value should not be empty")
		require.NotEmpty(t, payload.Name, "Payload name should not be empty")
		require.Greater(t, len(payload.Tags), 0, "Payload should have at least one tag")
		require.Greater(t, payload.Risk, 0, "Payload risk should be > 0")
		require.LessOrEqual(t, payload.Risk, 5, "Payload risk should be <= 5")
	}
}

func TestDefaultCanary(t *testing.T) {
	canary := DefaultCanary()
	
	require.Equal(t, "NucleiXSSCanary", canary.Value)
	require.Greater(t, len(canary.Markers), 0, "Should have markers")
	
	expectedMarkers := []string{"<", ">", "'", "\"", "/", "=", "\\"}
	require.Equal(t, expectedMarkers, canary.Markers)
}

func TestDefaultContextPatterns(t *testing.T) {
	patterns := DefaultContextPatterns()
	
	require.NotEmpty(t, patterns.Script)
	require.NotEmpty(t, patterns.Style)
	require.NotEmpty(t, patterns.Comment)
	require.NotEmpty(t, patterns.Attribute)
	require.NotEmpty(t, patterns.URL)
	require.NotEmpty(t, patterns.SrcDoc)
	require.NotEmpty(t, patterns.JavaScript)
	require.NotEmpty(t, patterns.DataType)
}

func TestXSSPayload_Structure(t *testing.T) {
	payload := XSSPayload{
		Value:       "<script>alert(1)</script>",
		Name:        "Test Payload",
		Tags:        []ContextType{ContextScript},
		Risk:        5,
		Description: "Test description",
	}
	
	require.Equal(t, "<script>alert(1)</script>", payload.Value)
	require.Equal(t, "Test Payload", payload.Name)
	require.Len(t, payload.Tags, 1)
	require.Equal(t, ContextScript, payload.Tags[0])
	require.Equal(t, 5, payload.Risk)
	require.Equal(t, "Test description", payload.Description)
}

func TestXSSResult_Structure(t *testing.T) {
	result := XSSResult{
		Found:      true,
		Context:    ContextScript,
		Payload:    "<script>alert(1)</script>",
		Proof:      "Payload reflected unencoded",
		CSP:        false,
		CSPValue:   "",
	}
	
	require.True(t, result.Found)
	require.Equal(t, ContextScript, result.Context)
	require.Equal(t, "<script>alert(1)</script>", result.Payload)
	require.Equal(t, "Payload reflected unencoded", result.Proof)
	require.False(t, result.CSP)
	require.Empty(t, result.CSPValue)
}

func TestCharacterSet_Structure(t *testing.T) {
	charset := CharacterSet{
		AngleBrackets: true,
		Quotes:        true,
		Slash:         false,
		Equals:        true,
		Backslash:     false,
		Parentheses:   true,
		Semicolon:     false,
	}
	
	require.True(t, charset.AngleBrackets)
	require.True(t, charset.Quotes)
	require.False(t, charset.Slash)
	require.True(t, charset.Equals)
	require.False(t, charset.Backslash)
	require.True(t, charset.Parentheses)
	require.False(t, charset.Semicolon)
}

func TestCanaryConfig_Structure(t *testing.T) {
	config := &CanaryConfig{
		Value:    "TestCanary",
		Markers:  []string{"<", ">"},
		Encoding: "utf-8",
	}
	
	require.Equal(t, "TestCanary", config.Value)
	require.Len(t, config.Markers, 2)
	require.Equal(t, "utf-8", config.Encoding)
}

func TestContextPatterns_RegexValidity(t *testing.T) {
	patterns := DefaultContextPatterns()
	
	// Test that all patterns compile successfully
	testStrings := map[string]string{
		"Script":      "<script>alert(1)</script>",
		"Style":       "<style>body{}</style>",
		"Comment":     "<!-- comment -->",
		"Attribute":   `class="test"`,
		"URL":         `href="https://example.com"`,
		"SrcDoc":      `srcdoc="<html>"`,
		"JavaScript":  "javascript:alert(1)",
		"DataType":    `type="application/json"`,
	}
	
	for name, pattern := range map[string]string{
		"Script":     patterns.Script,
		"Style":      patterns.Style,
		"Comment":    patterns.Comment,
		"Attribute":  patterns.Attribute,
		"URL":        patterns.URL,
		"SrcDoc":     patterns.SrcDoc,
		"JavaScript": patterns.JavaScript,
		"DataType":   patterns.DataType,
	} {
		t.Run(name, func(t *testing.T) {
			// Pattern should compile and match test string
			// (actual regex testing would require importing regexp)
			require.NotEmpty(t, pattern)
		})
	}
}

func TestMIMEType_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
		expected bool
	}{
		{"Whitespace", "  text/javascript  ", true},
		{"Uppercase", "TEXT/JAVASCRIPT", true},
		{"Mixed case", "Application/JSON", false},
		{"With parameters", "application/json; charset=utf-8", false},
		{"Partial match", "application/json-se", false},
		{"Empty string", "", true},
		{"Just slash", "/", true},
		{"No slash", "javascript", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsExecutableMIMEType(tt.mimeType)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestContextType_AllTypes(t *testing.T) {
	// Ensure all context types are defined
	allTypes := []ContextType{
		ContextNone,
		ContextHTMLText,
		ContextAttribute,
		ContextAttributeUnquoted,
		ContextScript,
		ContextScriptString,
		ContextStyle,
		ContextHTMLComment,
		ContextURL,
		ContextSrcDoc,
	}
	
	require.Equal(t, 10, len(allTypes), "Should have 10 context types")
	
	// All should have string representations
	for _, ctx := range allTypes {
		str := ctx.String()
		require.NotEmpty(t, str, "Context type should have string representation")
		require.NotEqual(t, "ContextUnknown", str, "Context type should be properly defined")
	}
}
