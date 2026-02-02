package xss

import (
	"testing"
)

func TestSelectPayloadsForHTMLBody(t *testing.T) {
	reflection := ReflectionInfo{
		Context: ContextHTMLBody,
		AvailableChars: CharacterSet{
			LessThan:    true,
			GreaterThan: true,
			SingleQuote: true,
			DoubleQuote: true,
			Slash:       true,
		},
	}

	payloads := SelectPayloads(reflection, map[string]interface{}{})

	if len(payloads) == 0 {
		t.Fatal("Expected payloads for HTML body context")
	}

	// Should include tag-based payloads
	found := false
	for _, p := range payloads {
		if p == "<img src=x onerror=alert(1)>" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected <img> payload for HTML body context")
	}
}

func TestSelectPayloadsForAttributeContext(t *testing.T) {
	reflection := ReflectionInfo{
		Context: ContextHTMLAttributeQuoted,
		AvailableChars: CharacterSet{
			LessThan:    true,
			GreaterThan: true,
			DoubleQuote: true,
		},
	}

	payloads := SelectPayloads(reflection, map[string]interface{}{})

	if len(payloads) == 0 {
		t.Fatal("Expected payloads for attribute context")
	}

	// Should include quote breakout payloads
	found := false
	for _, p := range payloads {
		if p == "\" onload=alert(1) x=\"" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected quote breakout payload for attribute context")
	}
}

func TestFilterPayloadsByMissingChars(t *testing.T) {
	// No < and > available
	reflection := ReflectionInfo{
		Context: ContextHTMLBody,
		AvailableChars: CharacterSet{
			LessThan:    false,
			GreaterThan: false,
			SingleQuote: true,
			DoubleQuote: true,
		},
	}

	payloads := SelectPayloads(reflection, map[string]interface{}{})

	// Should have no payloads since < > are required for HTML body injection
	if len(payloads) != 0 {
		t.Errorf("Expected no payloads without < and >, got %d", len(payloads))
	}
}

func TestFilterPayloadsByMissingQuotes(t *testing.T) {
	// No quotes available in attribute context
	reflection := ReflectionInfo{
		Context: ContextHTMLAttributeQuoted,
		AvailableChars: CharacterSet{
			LessThan:    true,
			GreaterThan: true,
			SingleQuote: false,
			DoubleQuote: false,
			Slash:       true,
		},
	}

	payloads := SelectPayloads(reflection, map[string]interface{}{})

	// Payloads requiring quote breakout should be filtered
	for _, p := range payloads {
		if p == "\" onload=alert(1) x=\"" || p == "' onload=alert(1) x='" {
			t.Errorf("Payload %q should be filtered (quotes not available)", p)
		}
	}
}

func TestMaxVerificationAttempts(t *testing.T) {
	reflection := ReflectionInfo{
		Context: ContextHTMLBody,
		AvailableChars: CharacterSet{
			LessThan:    true,
			GreaterThan: true,
			SingleQuote: true,
			DoubleQuote: true,
			Slash:       true,
		},
	}

	// Set max attempts to 1
	params := map[string]interface{}{
		"max_verification_attempts": 1,
	}

	payloads := SelectPayloads(reflection, params)

	if len(payloads) > 1 {
		t.Errorf("Expected max 1 payload, got %d", len(payloads))
	}
}

func TestScriptContextPayloads(t *testing.T) {
	reflection := ReflectionInfo{
		Context: ContextScriptString,
		AvailableChars: CharacterSet{
			SingleQuote: true,
			DoubleQuote: true,
			Slash:       true,
		},
	}

	payloads := SelectPayloads(reflection, map[string]interface{}{})

	if len(payloads) == 0 {
		t.Fatal("Expected payloads for script string context")
	}

	// Should include script breakout payloads
	foundSingleQuote := false
	foundDoubleQuote := false

	for _, p := range payloads {
		if p == "';alert(1);//" {
			foundSingleQuote = true
		}
		if p == "\";alert(1);//" {
			foundDoubleQuote = true
		}
	}

	if !foundSingleQuote || !foundDoubleQuote {
		t.Error("Expected both single and double quote script breakout payloads")
	}
}

func TestCanUsePayload(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		chars   CharacterSet
		context ContextType
		want    bool
	}{
		{
			name:    "HTML body with required chars",
			payload: "<img src=x onerror=alert(1)>",
			chars: CharacterSet{
				LessThan:    true,
				GreaterThan: true,
			},
			context: ContextHTMLBody,
			want:    true,
		},
		{
			name:    "HTML body without required chars",
			payload: "<img src=x onerror=alert(1)>",
			chars: CharacterSet{
				LessThan:    false,
				GreaterThan: true,
			},
			context: ContextHTMLBody,
			want:    false,
		},
		{
			name:    "Double quote breakout with char available",
			payload: "\" onload=alert(1)",
			chars: CharacterSet{
				DoubleQuote: true,
			},
			context: ContextHTMLAttributeQuoted,
			want:    true,
		},
		{
			name:    "Double quote breakout without char",
			payload: "\" onload=alert(1)",
			chars: CharacterSet{
				DoubleQuote: false,
			},
			context: ContextHTMLAttributeQuoted,
			want:    false,
		},
		{
			name:    "Tag closing with slash",
			payload: "</script><script>alert(1)</script>",
			chars: CharacterSet{
				LessThan:    true,
				GreaterThan: true,
				Slash:       true,
			},
			context: ContextScriptString,
			want:    true,
		},
		{
			name:    "Tag closing without slash",
			payload: "</script><script>alert(1)</script>",
			chars: CharacterSet{
				LessThan:    true,
				GreaterThan: true,
				Slash:       false,
			},
			context: ContextScriptString,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canUsePayload(tt.payload, tt.chars, tt.context)
			if got != tt.want {
				t.Errorf("canUsePayload() = %v, want %v", got, tt.want)
			}
		})
	}
}
