package expressions

import (
	"strings"
	"testing"
)

// TestWave10PayloadURLParamInjection asserts parameter replacement
func TestWave10PayloadURLParamInjection(t *testing.T) {
	injectParam := func(rawURL, param, value string) string {
		if strings.Contains(rawURL, "?") {
			return rawURL + "&" + param + "=" + value
		}
		return rawURL + "?" + param + "=" + value
	}

	res := injectParam("https://example.com/api", "q", "payload")
	if res != "https://example.com/api?q=payload" {
		t.Errorf("expected clean query param injection, got %s", res)
	}

	res2 := injectParam("https://example.com/api?debug=true", "q", "payload")
	if res2 != "https://example.com/api?debug=true&q=payload" {
		t.Errorf("expected appended query param, got %s", res2)
	}
}

// TestWave10PayloadEncodingGuard asserts base64 string sanity
func TestWave10PayloadEncodingGuard(t *testing.T) {
	isValidBase64Char := func(c rune) bool {
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
	}

	sample := "aGVsbG8td29ybGQ="
	for _, ch := range sample {
		if !isValidBase64Char(ch) {
			t.Errorf("character %c is not valid base64", ch)
		}
	}
}
